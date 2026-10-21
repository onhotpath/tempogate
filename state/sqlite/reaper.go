package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
)

const (
	defaultReapInterval  = 5 * time.Minute
	defaultReapBatchSize = 500

	// denylistGrace keeps a revoked integration key's jti denylisted for a
	// while past the token's exp, so a verifier whose clock runs behind
	// still refuses it.
	denylistGrace = time.Hour
)

// expiringTables hold rows that are dead once expires_at passes: every
// reader already refuses an expired row, so deleting it changes no answer.
var expiringTables = []string{"auth_requests", "auth_codes", "device_codes", "browser_sessions"}

// Reaper deletes expired state. Without it, rows nobody consumes (an
// abandoned /authorize, an unused device code) stay forever, and an
// anonymous caller can fill the volume with them.
//
// Expiry is decided in Go, not SQL: the driver stores timestamps as
// time.Time.String() text, which does not order lexically across zones.
// Each table is walked by rowid a batch at a time so the single SQLite
// connection is released between batches and logins are not stalled
// behind a large sweep.
type Reaper struct {
	store              *Store
	interval           time.Duration
	refreshMaxLifetime time.Duration
	batch              int
	now                func() time.Time
	logger             *zap.Logger
}

type ReaperOption func(*Reaper)

// WithReaperInterval sets how often Run sweeps; 0 disables it.
func WithReaperInterval(d time.Duration) ReaperOption {
	return func(r *Reaper) { r.interval = d }
}

// WithReaperRefreshMaxLifetime is OIDC_REFRESH_MAX_LIFETIME: a refresh
// family is dead once its sign-in is this old. 0 keeps families until
// every row has expired and been consumed or revoked.
func WithReaperRefreshMaxLifetime(d time.Duration) ReaperOption {
	return func(r *Reaper) { r.refreshMaxLifetime = d }
}

// WithReaperBatchSize sets how many rows one statement reads or deletes.
// Non-positive keeps the default.
func WithReaperBatchSize(n int) ReaperOption {
	return func(r *Reaper) {
		if n > 0 {
			r.batch = n
		}
	}
}

// WithReaperClock swaps the clock. For tests.
func WithReaperClock(now func() time.Time) ReaperOption {
	return func(r *Reaper) { r.now = now }
}

func WithReaperLogger(l *zap.Logger) ReaperOption {
	return func(r *Reaper) { r.logger = l }
}

func NewReaper(store *Store, opts ...ReaperOption) *Reaper {
	r := &Reaper{
		store:    store,
		interval: defaultReapInterval,
		batch:    defaultReapBatchSize,
		now:      func() time.Time { return time.Now().UTC() },
		logger:   zap.NewNop(),
	}
	for _, o := range opts {
		o(r)
	}
	return r
}

// Run sweeps once at start, then every interval, until ctx is cancelled.
// A failed sweep is logged and retried on the next tick: the server keeps
// serving either way.
func (r *Reaper) Run(ctx context.Context) error {
	if r.interval <= 0 {
		return nil
	}
	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		r.sweep(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

func (r *Reaper) sweep(ctx context.Context) {
	counts, err := r.Reap(ctx)
	if ctx.Err() != nil {
		return // shutting down; the interrupted batch is retried next start
	}
	if err != nil {
		r.store.observer.ObserveDBError("reap")
		r.logger.Warn("reaping expired state failed", zap.Error(err))
	}
	fields := make([]zap.Field, 0, len(counts))
	for table, n := range counts {
		fields = append(fields, zap.Int(table, n))
	}
	r.logger.Debug("reaped expired state", fields...)
}

// Reap runs one sweep and reports the rows deleted per table. A failure on
// one table does not stop the others.
func (r *Reaper) Reap(ctx context.Context) (map[string]int, error) {
	now := r.now()
	counts := map[string]int{}
	var errs []error
	for _, table := range expiringTables {
		n, err := r.reapExpired(ctx, table, now)
		counts[table] = n
		if err != nil {
			errs = append(errs, fmt.Errorf("sqlite: reap %s: %w", table, err))
		}
	}
	n, err := r.reapRefreshFamilies(ctx, now)
	counts["refresh_tokens"] = n
	if err != nil {
		errs = append(errs, fmt.Errorf("sqlite: reap refresh_tokens: %w", err))
	}
	n, err = r.reapDenylist(ctx, now)
	counts["jti_denylist"] = n
	if err != nil {
		errs = append(errs, fmt.Errorf("sqlite: reap jti_denylist: %w", err))
	}
	return counts, errors.Join(errs...)
}

func (r *Reaper) reapExpired(ctx context.Context, table string, now time.Time) (int, error) {
	deleted := 0
	var expired []any
	err := r.pages(ctx,
		// #nosec G202 -- table is one of the constant expiringTables.
		`SELECT rowid, expires_at FROM `+table+` WHERE rowid > ? ORDER BY rowid LIMIT ?`,
		func(rows *sql.Rows) (int64, error) {
			var (
				id  int64
				exp time.Time
			)
			if err := rows.Scan(&id, &exp); err != nil {
				return 0, err
			}
			if now.After(exp) {
				expired = append(expired, id)
			}
			return id, nil
		},
		func() error {
			n, err := r.deleteIn(ctx, `DELETE FROM `+table+` WHERE rowid IN `, expired)
			deleted += n
			expired = expired[:0]
			return err
		},
	)
	return deleted, err
}

// reapRefreshFamilies deletes whole families, never single rows. A consumed
// token is kept as a tombstone so that presenting it again is recognised
// as reuse and revokes the family (migration 0011); deleting it while the
// family still has a usable token would turn that replay into a plain
// "unknown token" and leave the newer token alive. So a family goes only
// when every row is dead: the sign-in is past OIDC_REFRESH_MAX_LIFETIME,
// or the row has expired and was consumed or revoked. Nothing can be added
// to such a family (rotation needs a live row), so deleting it later in
// the sweep is race-free.
func (r *Reaper) reapRefreshFamilies(ctx context.Context, now time.Time) (int, error) {
	seen := map[string]bool{} // family -> has a row that is not dead
	err := r.pages(ctx,
		`SELECT rowid, family_id, auth_time, expires_at, consumed_at IS NOT NULL OR revoked_at IS NOT NULL
		 FROM refresh_tokens WHERE rowid > ? ORDER BY rowid LIMIT ?`,
		func(rows *sql.Rows) (int64, error) {
			var (
				id                int64
				family            string
				authTime, expires time.Time
				spent             bool
			)
			if err := rows.Scan(&id, &family, &authTime, &expires, &spent); err != nil {
				return 0, err
			}
			ended := r.refreshMaxLifetime > 0 && !now.Before(authTime.Add(r.refreshMaxLifetime))
			dead := ended || (spent && now.After(expires))
			seen[family] = seen[family] || !dead
			return id, nil
		},
		func() error { return nil },
	)
	if err != nil {
		return 0, err
	}

	var families []any
	for f, alive := range seen {
		if !alive {
			families = append(families, f)
		}
	}
	deleted := 0
	for len(families) > 0 {
		chunk := families[:min(r.batch, len(families))]
		families = families[len(chunk):]
		n, err := r.deleteIn(ctx, `DELETE FROM refresh_tokens WHERE family_id IN `, chunk)
		deleted += n
		if err != nil {
			return deleted, err
		}
	}
	return deleted, nil
}

// reapDenylist deletes a revoked jti once the token it names has expired:
// the verifier refuses an expired token anyway. Only integration keys are
// denylisted, and the key's expires_at is its JWT's exp; a key without one
// (or a jti without a key row) never expires and is kept.
func (r *Reaper) reapDenylist(ctx context.Context, now time.Time) (int, error) {
	deleted := 0
	var expired []any
	err := r.pages(ctx,
		`SELECT d.rowid, k.expires_at
		 FROM jti_denylist d JOIN integration_keys k ON k.jti = d.jti
		 WHERE d.rowid > ? AND k.expires_at IS NOT NULL
		 ORDER BY d.rowid LIMIT ?`,
		func(rows *sql.Rows) (int64, error) {
			var (
				id  int64
				exp time.Time
			)
			if err := rows.Scan(&id, &exp); err != nil {
				return 0, err
			}
			if now.After(exp.Add(denylistGrace)) {
				expired = append(expired, id)
			}
			return id, nil
		},
		func() error {
			n, err := r.deleteIn(ctx, `DELETE FROM jti_denylist WHERE rowid IN `, expired)
			deleted += n
			expired = expired[:0]
			return err
		},
	)
	return deleted, err
}

// pages runs query (which takes a rowid cursor and a limit, and selects
// rowid first) a batch at a time. scan reads one row and returns its rowid;
// flush runs after each batch, once the rows are closed, since the store
// may hold only one connection.
func (r *Reaper) pages(ctx context.Context, query string, scan func(*sql.Rows) (int64, error), flush func() error) error {
	var cursor int64
	for {
		read, err := r.page(ctx, query, &cursor, scan)
		if err != nil {
			return err
		}
		if err := flush(); err != nil {
			return err
		}
		if read < r.batch {
			return nil
		}
	}
}

func (r *Reaper) page(ctx context.Context, query string, cursor *int64, scan func(*sql.Rows) (int64, error)) (int, error) {
	rows, err := r.store.db.QueryContext(ctx, query, *cursor, r.batch)
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()
	read := 0
	for rows.Next() {
		id, err := scan(rows)
		if err != nil {
			return read, err
		}
		*cursor = id
		read++
	}
	return read, rows.Err()
}

// deleteIn runs stmt (ending in "IN ") over args and reports rows deleted.
func (r *Reaper) deleteIn(ctx context.Context, stmt string, args []any) (int, error) {
	if len(args) == 0 {
		return 0, nil
	}
	placeholders := "(" + strings.TrimSuffix(strings.Repeat("?,", len(args)), ",") + ")"
	res, err := r.store.db.ExecContext(ctx, stmt+placeholders, args...)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}
