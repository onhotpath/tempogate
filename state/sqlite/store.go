// Package sqlite is the concrete SQLite-backed implementation that satisfies
// the per-consumer state interfaces defined across the codebase via Go's
// structural typing (see state/doc.go).
//
// Not-found and duplicate errors are the bare sentinels, never annotated with
// the key they were looked up by: those keys are auth codes, refresh tokens,
// device and user codes, session ids, and OAuth state, and error text ends up
// in logs.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"go.uber.org/zap"
	// Pure-Go SQLite driver registered under the "sqlite" name with database/sql.
	_ "modernc.org/sqlite"
)

type options struct {
	path        string
	maxConns    int
	busyTimeout time.Duration
	logger      *zap.Logger
	observer    ErrorObserver
}

// ErrorObserver is told every store operation that failed with a database
// error, under a fixed op name (e.g. "consume_refresh"). Not-found results
// are protocol outcomes, not errors, and are never reported. The metrics
// package satisfies it; this package never imports Prometheus.
type ErrorObserver interface {
	ObserveDBError(op string)
}

type Option func(*options)

func WithPath(p string) Option { return func(o *options) { o.path = p } }

func WithMaxConns(n int) Option { return func(o *options) { o.maxConns = n } }

// WithLogger receives the warnings New raises about file permissions it
// cannot or will not fix.
func WithLogger(l *zap.Logger) Option { return func(o *options) { o.logger = l } }

func WithBusyTimeout(d time.Duration) Option { return func(o *options) { o.busyTimeout = d } }

// WithErrorObserver reports failed operations to obs. Nil keeps the no-op
// default.
func WithErrorObserver(obs ErrorObserver) Option {
	return func(o *options) {
		if obs != nil {
			o.observer = obs
		}
	}
}

type nopObserver struct{}

func (nopObserver) ObserveDBError(string) {}

func defaultOptions() *options {
	return &options{
		path:        "/var/lib/tempogate/state.db",
		maxConns:    1,
		busyTimeout: 5 * time.Second,
		logger:      zap.NewNop(),
		observer:    nopObserver{},
	}
}

type Store struct {
	db       *sql.DB
	probe    *sql.DB
	observer ErrorObserver
}

func New(opts ...Option) (*Store, error) {
	o := defaultOptions()
	for _, opt := range opts {
		opt(o)
	}
	if o.path == "" {
		return nil, fmt.Errorf("sqlite: empty path")
	}
	if err := restrictFiles(o.path, o.logger); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", dsn(o))
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	db.SetMaxOpenConns(o.maxConns)

	probe, err := sql.Open("sqlite", probeDSN(o))
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: open probe: %w", err)
	}
	// No idle connections: every Probe opens the file afresh, which is the
	// point (see Probe).
	probe.SetMaxIdleConns(0)
	probe.SetMaxOpenConns(1)

	return &Store{db: db, probe: probe, observer: o.observer}, nil
}

// restrictFiles makes the database owner-only before SQLite opens it: the
// file holds signing keys and session state, and SQLite otherwise creates it
// (and its -wal / -shm) with the process umask, typically world-readable.
// SQLite gives -wal and -shm the mode of the database file when it creates
// them, so creating the database 0600 covers those too; files left by an
// earlier version are tightened here.
//
// The directory is created 0700 when missing. An existing one is the
// operator's (a mounted volume, a shared /tmp) and is not changed; it is
// only reported when other users can enter it. Group access is expected: it
// is how a Kubernetes fsGroup volume grants the pod its storage.
func restrictFiles(path string, logger *zap.Logger) error {
	dir := filepath.Dir(path)
	info, err := os.Stat(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("sqlite: create state directory: %w", err)
		}
	case err != nil:
		return fmt.Errorf("sqlite: stat state directory: %w", err)
	case info.Mode().Perm()&0o007 != 0:
		logger.Warn("state directory is accessible to other users; restrict it to the tempogate user",
			zap.String("dir", dir), zap.Stringer("mode", info.Mode().Perm()))
	}

	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) // #nosec G304 -- operator-configured STATE_SQLITE_PATH.
	if err != nil {
		return fmt.Errorf("sqlite: create database file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("sqlite: create database file: %w", err)
	}
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		// A file owned by another user (say, created by a migrate run as
		// root) cannot be tightened by us; refusing to start would turn a
		// hardening step into an outage, so only warn.
		if err := os.Chmod(p, 0o600); err != nil && !errors.Is(err, fs.ErrNotExist) {
			logger.Warn("could not restrict state file to owner-only", zap.String("file", p), zap.Error(err))
		}
	}
	return nil
}

func dsn(o *options) string {
	q := url.Values{}
	q.Add("_pragma", fmt.Sprintf("busy_timeout(%d)", o.busyTimeout.Milliseconds()))
	q.Add("_pragma", "journal_mode(wal)")
	q.Add("_pragma", "foreign_keys(on)")
	return "file:" + o.path + "?" + q.Encode()
}

// probeDSN opens the same file read-only, so a probe can never create an
// empty database where the real one has vanished.
func probeDSN(o *options) string {
	q := url.Values{}
	q.Add("mode", "ro")
	q.Add("_pragma", fmt.Sprintf("busy_timeout(%d)", o.busyTimeout.Milliseconds()))
	return "file:" + o.path + "?" + q.Encode()
}

func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

// Probe reports whether the store can serve requests right now; /readyz
// calls it. Pinging the serving pool is not enough: its connection holds an
// open descriptor, so it keeps reading and writing a database file that has
// been deleted, replaced or truncated underneath it (a lost or remounted
// volume), silently losing every write. Probe therefore also opens the file
// the configured path names now, read-only, and reads the migrations table
// from it.
func (s *Store) Probe(ctx context.Context) error {
	if err := s.db.PingContext(ctx); err != nil {
		return s.fail("probe", fmt.Errorf("sqlite: ping: %w", err))
	}
	var one int
	if err := s.probe.QueryRowContext(ctx, `SELECT 1 FROM schema_migrations LIMIT 1`).Scan(&one); err != nil {
		return s.fail("probe", fmt.Errorf("sqlite: probe: %w", err))
	}
	return nil
}

// fail reports a failed operation to the observer and returns err unchanged,
// so call sites keep their own error context.
func (s *Store) fail(op string, err error) error {
	s.observer.ObserveDBError(op)
	return err
}

func (s *Store) Close() error {
	return errors.Join(s.db.Close(), s.probe.Close())
}
