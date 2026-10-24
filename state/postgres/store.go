// Package postgres is the PostgreSQL implementation of the per-consumer
// state interfaces defined across the codebase (see state/doc.go), for
// deployments that run several replicas over one shared database. It uses
// the native pgx API over a pgxpool, never database/sql.
//
// Where SQLite relies on its single writer, this package takes row locks
// under READ COMMITTED: a refresh_families row (FOR SHARE on rotation,
// updated first on revocation), the device code row on poll (FOR UPDATE),
// the active keypairs on retirement (FOR UPDATE), and advisory transaction
// locks for migration and first-boot key generation. The reaper deletes in
// FOR UPDATE SKIP LOCKED batches, so every replica can run it.
//
// Not-found and duplicate errors are the bare sentinels, never annotated with
// the key they were looked up by: those keys are auth codes, refresh tokens,
// device and user codes, session ids, and OAuth state, and error text ends up
// in logs.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/onhotpath/tempogate/observe"
	"github.com/onhotpath/tempogate/redact"
	"github.com/onhotpath/tempogate/state/internal/changefeed"
	"github.com/onhotpath/tempogate/state/internal/instrument"
)

type options struct {
	dsn                  string
	dsnFile              string
	listenDSN            string
	maxConns             int
	connMaxIdleTime      time.Duration
	allowInsecureSSLMode bool
	logger               *zap.Logger
	meter                observe.Meter
	tracer               observe.Tracer
	redaction            *redact.Set
	migrations           fs.FS
}

type Option func(*options)

// WithDSN is the connection string (URL or keyword/value form) for the
// serving pool. Set it or WithDSNFile, not both.
func WithDSN(dsn string) Option { return func(o *options) { o.dsn = dsn } }

// WithDSNFile reads the connection string from path, e.g. a mounted
// Kubernetes Secret. The file is read again for every new connection, so a
// rotated password takes effect without a restart.
func WithDSNFile(path string) Option { return func(o *options) { o.dsnFile = path } }

// WithListenDSN is the connection string for the one LISTEN connection
// behind the change feed. Empty uses the serving DSN; set it to reach
// Postgres directly when the serving DSN goes through a transaction-mode
// pooler, which cannot hold a LISTEN.
func WithListenDSN(dsn string) Option { return func(o *options) { o.listenDSN = dsn } }

// WithMaxConns caps the serving pool. First-boot key generation holds one
// connection while it works on another, so it must be at least 2.
func WithMaxConns(n int) Option { return func(o *options) { o.maxConns = n } }

// WithConnMaxIdleTime closes pooled connections idle for longer than d.
func WithConnMaxIdleTime(d time.Duration) Option {
	return func(o *options) { o.connMaxIdleTime = d }
}

// WithAllowInsecureSSLMode accepts an sslmode weaker than verify-full for a
// host that is not loopback. Development only: see checkTLS.
func WithAllowInsecureSSLMode(allow bool) Option {
	return func(o *options) { o.allowInsecureSSLMode = allow }
}

// WithLogger receives the store's warnings: an insecure sslmode allowed by
// WithAllowInsecureSSLMode, and a change-feed connection that dropped.
func WithLogger(l *zap.Logger) Option { return func(o *options) { o.logger = l } }

// WithMeter declares the store's metrics (failed operations, by op) on m.
// Nil records nothing.
func WithMeter(m observe.Meter) Option { return func(o *options) { o.meter = m } }

// WithTracer makes every operation run inside a traced request a span of its
// own. Nil starts no spans.
func WithTracer(t observe.Tracer) Option { return func(o *options) { o.tracer = t } }

// WithRedaction declares the password of every DSN the store reads in s, so
// no exported span carries it. Nil declares nothing.
func WithRedaction(s *redact.Set) Option { return func(o *options) { o.redaction = s } }

func defaultOptions() *options {
	return &options{
		maxConns:        10,
		connMaxIdleTime: 30 * time.Minute,
		logger:          zap.NewNop(),
		migrations:      migrationsFS,
	}
}

type Store struct {
	pool       *pgxpool.Pool
	ops        *instrument.Ops
	logger     *zap.Logger
	migrations fs.FS

	changes  changefeed.Hub
	listen   connSource
	feedOnce sync.Once
	feedUp   chan struct{} // closed once the first LISTEN attempt finished
	stopFeed context.CancelFunc
	feedDone chan struct{}
}

// New builds the store over a pool that connects lazily: an unreachable
// database fails the first query (Ping, Migrate, IsCurrent), not New. A DSN
// whose TLS settings do not authenticate a remote server fails New, unless
// WithAllowInsecureSSLMode.
func New(opts ...Option) (*Store, error) {
	o := defaultOptions()
	for _, opt := range opts {
		opt(o)
	}
	if (o.dsn == "") == (o.dsnFile == "") {
		return nil, errors.New("postgres: set exactly one of STATE_POSTGRES_DSN and STATE_POSTGRES_DSN_FILE")
	}
	if o.maxConns < 2 {
		return nil, fmt.Errorf("postgres: STATE_POSTGRES_MAX_CONNS must be at least 2, got %d", o.maxConns)
	}
	if o.connMaxIdleTime < 0 {
		return nil, fmt.Errorf("postgres: STATE_POSTGRES_CONN_MAX_IDLE_TIME must not be negative, got %s", o.connMaxIdleTime)
	}

	ops, err := instrument.New(o.meter, o.tracer)
	if err != nil {
		return nil, fmt.Errorf("postgres: %w", err)
	}

	serving := connSource{dsn: o.dsn, file: o.dsnFile, setting: "STATE_POSTGRES_DSN", allowInsecure: o.allowInsecureSSLMode, logger: o.logger, redaction: o.redaction}
	if o.dsnFile != "" {
		serving.setting = "STATE_POSTGRES_DSN_FILE"
	}
	cfg, err := serving.poolConfig()
	if err != nil {
		return nil, err
	}
	cfg.MaxConns = int32(min(o.maxConns, 1<<20)) // #nosec G115 -- clamped above.
	cfg.MaxConnIdleTime = o.connMaxIdleTime
	if o.dsnFile != "" {
		cfg.BeforeConnect = serving.beforeConnect
	}
	cfg.AfterConnect = func(_ context.Context, c *pgx.Conn) error {
		registerUTC(c)
		return nil
	}

	listen := serving
	if o.listenDSN != "" {
		listen = connSource{dsn: o.listenDSN, setting: "STATE_POSTGRES_LISTEN_DSN", allowInsecure: o.allowInsecureSSLMode, logger: o.logger, redaction: o.redaction}
		if _, err := listen.connConfig(); err != nil {
			return nil, err
		}
	}

	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		return nil, fmt.Errorf("postgres: create pool: %w", err)
	}
	return &Store{
		pool:       pool,
		ops:        ops,
		logger:     o.logger,
		migrations: o.migrations,
		listen:     listen,
		feedUp:     make(chan struct{}),
		feedDone:   make(chan struct{}),
	}, nil
}

// registerUTC makes timestamptz values scan as UTC, the contract's zone
// (state/doc.go), whatever the server's or the process's time zone.
func registerUTC(c *pgx.Conn) {
	c.TypeMap().RegisterType(&pgtype.Type{
		Name:  "timestamptz",
		OID:   pgtype.TimestamptzOID,
		Codec: &pgtype.TimestamptzCodec{ScanLocation: time.UTC},
	})
}

func (s *Store) Ping(ctx context.Context) error {
	if err := s.pool.Ping(ctx); err != nil {
		return fmt.Errorf("postgres: ping: %w", err)
	}
	return nil
}

// Probe reports whether the store can serve requests right now; /readyz
// calls it. It takes a pooled connection and reads the migrations table, so
// it fails while the database is unreachable, refuses this role, or was
// replaced by an empty one.
func (s *Store) Probe(ctx context.Context) error {
	ctx, op := s.ops.Start(ctx, "probe")
	defer op.End()
	var one int
	if err := s.pool.QueryRow(ctx, `SELECT 1 FROM schema_migrations LIMIT 1`).Scan(&one); err != nil {
		return op.Fail(fmt.Errorf("postgres: probe: %w", err))
	}
	return nil
}

// Close stops the change feed, if it ever started, and closes the pool.
func (s *Store) Close() error {
	s.feedOnce.Do(func() { close(s.feedUp); close(s.feedDone) })
	if s.stopFeed != nil {
		s.stopFeed()
	}
	<-s.feedDone
	s.pool.Close()
	return nil
}

// inTx runs fn in a READ COMMITTED transaction and commits it when fn
// returns nil. Any error from fn is returned as is, after the rollback.
func (s *Store) inTx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit: %w", err)
	}
	return nil
}

// isUniqueViolation reports a duplicate key, the one constraint failure
// callers distinguish.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
