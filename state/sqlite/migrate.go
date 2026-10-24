package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"

	"github.com/onhotpath/tempogate/internal/clock"
	"github.com/onhotpath/tempogate/state/internal/migration"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// schemaVersionDDL has no DEFAULT on applied_at: the application owns the
// clock (state/doc.go), so the runner binds it. Databases created before
// that keep their unused DEFAULT CURRENT_TIMESTAMP.
const schemaVersionDDL = `CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INTEGER PRIMARY KEY,
    name       TEXT NOT NULL,
    applied_at TIMESTAMP NOT NULL
)`

// IsCurrent returns nil when every embedded migration is recorded in
// schema_migrations, and otherwise the operator-facing message
// migration.Check describes.
func (s *Store) IsCurrent(ctx context.Context) error {
	ctx, op := s.ops.Start(ctx, "is_current")
	defer op.End()
	if _, err := s.db.ExecContext(ctx, schemaVersionDDL); err != nil {
		return op.Fail(fmt.Errorf("sqlite: ensure schema_migrations: %w", err))
	}

	migs, err := loadMigrations()
	if err != nil {
		return err
	}

	applied, err := loadAppliedVersions(ctx, s.db)
	if err != nil {
		return op.Fail(err)
	}
	return migration.Check(migs, applied)
}

// Migrate applies every embedded migration whose version has not yet been
// recorded in schema_migrations. Safe to run repeatedly; second invocations
// are a no-op.
func (s *Store) Migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, schemaVersionDDL); err != nil {
		return fmt.Errorf("sqlite: create schema_migrations: %w", err)
	}

	migs, err := loadMigrations()
	if err != nil {
		return err
	}

	applied, err := loadAppliedVersions(ctx, s.db)
	if err != nil {
		return err
	}

	for _, m := range migration.Pending(migs, applied) {
		if err := applyMigration(ctx, s.db, m); err != nil {
			return err
		}
	}
	return nil
}

func loadMigrations() ([]migration.Migration, error) {
	return migration.Load(migrationsFS, "migrations", "sqlite")
}

func loadAppliedVersions(ctx context.Context, db *sql.DB) (map[int]struct{}, error) {
	rows, err := db.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("sqlite: read schema_migrations: %w", err)
	}
	defer func() { _ = rows.Close() }()

	applied := map[int]struct{}{}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("sqlite: scan version: %w", err)
		}
		applied[v] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: rows: %w", err)
	}
	return applied, nil
}

func applyMigration(ctx context.Context, db *sql.DB, m migration.Migration) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlite: begin tx for %d_%s: %w", m.Version, m.Name, err)
	}
	if _, err := tx.ExecContext(ctx, m.SQL); err != nil {
		return errors.Join(
			fmt.Errorf("sqlite: apply %d_%s: %w", m.Version, m.Name, err),
			tx.Rollback(),
		)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)`,
		m.Version, m.Name, clock.Now(),
	); err != nil {
		return errors.Join(
			fmt.Errorf("sqlite: record %d_%s: %w", m.Version, m.Name, err),
			tx.Rollback(),
		)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlite: commit %d_%s: %w", m.Version, m.Name, err)
	}
	return nil
}
