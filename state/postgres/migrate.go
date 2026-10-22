package postgres

import (
	"context"
	"embed"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/onhotpath/tempogate/internal/clock"
	"github.com/onhotpath/tempogate/state/internal/migration"
)

// The schema starts from 0014_baseline.sql, equal to the SQLite schema at
// its migration 0014; from there on every migration is a pair, one file in
// each backend's migrations directory with the same NNNN_name (enforced by
// TestMigrationsPairWithSQLite). Migrations are expand/contract, because a
// rolling update runs two versions against one database.
//
// All pending files run in one transaction, so there is no "dirty" state to
// recover from: a failing file leaves the schema as it was. Postgres DDL is
// transactional, so that covers every file written so far; a migration that
// cannot run in a transaction (CREATE INDEX CONCURRENTLY) would need a
// per-file opt-out, to be added with the first one that needs it.
//
//go:embed migrations/*.sql
var migrationsFS embed.FS

// migrationLockID is the pg_advisory_xact_lock key serialising `migrate`
// runs across replicas. A transaction-level lock is released by COMMIT or
// ROLLBACK, so it also works through a transaction-mode pooler and cannot
// outlive a crashed runner.
const migrationLockID int64 = 0x74676d6967726174 // "tgmigrat"

// migrationLockTimeout bounds how long one migration statement waits for a
// table lock held by serving replicas, so a migration stuck behind a long
// transaction fails instead of queueing every query behind it. The advisory
// lock above is taken before it applies, so concurrent runs wait for each
// other as long as their context allows.
const migrationLockTimeout = "5s"

const schemaVersionDDL = `CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INTEGER PRIMARY KEY,
    name       TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL
)`

// IsCurrent returns nil when every embedded migration is recorded in
// schema_migrations, and otherwise the operator-facing message
// migration.Check describes. It only reads: a database never migrated reads
// as schema version 0.
func (s *Store) IsCurrent(ctx context.Context) error {
	migs, err := s.loadMigrations()
	if err != nil {
		return err
	}

	applied, err := loadAppliedVersions(ctx, s.pool)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "42P01" { // undefined_table
		applied, err = map[int]struct{}{}, nil
	}
	if err != nil {
		return s.fail("is_current", err)
	}
	return migration.Check(migs, applied)
}

// Migrate applies every embedded migration whose version has not yet been
// recorded in schema_migrations, all in one transaction under
// migrationLockID. Runs racing from several replicas apply each version
// once: the versions are read only after the lock is held. Safe to run
// repeatedly; second invocations are a no-op.
func (s *Store) Migrate(ctx context.Context) error {
	migs, err := s.loadMigrations()
	if err != nil {
		return err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin migrations: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, migrationLockID); err != nil {
		return fmt.Errorf("postgres: lock migrations: %w", err)
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout', $1, true)`, migrationLockTimeout); err != nil {
		return fmt.Errorf("postgres: set lock_timeout: %w", err)
	}
	if _, err := tx.Exec(ctx, schemaVersionDDL); err != nil {
		return fmt.Errorf("postgres: create schema_migrations: %w", err)
	}

	applied, err := loadAppliedVersions(ctx, tx)
	if err != nil {
		return err
	}

	for _, m := range migration.Pending(migs, applied) {
		if err := applyMigration(ctx, tx, m); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit migrations: %w", err)
	}
	return nil
}

func (s *Store) loadMigrations() ([]migration.Migration, error) {
	return migration.Load(s.migrations, "migrations", "postgres")
}

// querier is the Query half shared by *pgxpool.Pool and pgx.Tx.
type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

func loadAppliedVersions(ctx context.Context, q querier) (map[int]struct{}, error) {
	rows, err := q.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("postgres: read schema_migrations: %w", err)
	}
	versions, err := pgx.CollectRows(rows, pgx.RowTo[int])
	if err != nil {
		return nil, fmt.Errorf("postgres: read schema_migrations: %w", err)
	}

	applied := make(map[int]struct{}, len(versions))
	for _, v := range versions {
		applied[v] = struct{}{}
	}
	return applied, nil
}

// applyMigration runs m and records it inside the caller's transaction. A
// file runs without arguments, so pgx sends it over the simple protocol,
// which allows several statements in one file.
func applyMigration(ctx context.Context, tx pgx.Tx, m migration.Migration) error {
	if _, err := tx.Exec(ctx, m.SQL); err != nil {
		return fmt.Errorf("postgres: apply %d_%s: %w", m.Version, m.Name, err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO schema_migrations (version, name, applied_at) VALUES ($1, $2, $3)`,
		m.Version, m.Name, clock.Now(),
	); err != nil {
		return fmt.Errorf("postgres: record %d_%s: %w", m.Version, m.Name, err)
	}
	return nil
}
