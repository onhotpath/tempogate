package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

const schemaVersionDDL = `CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INTEGER PRIMARY KEY,
    name       TEXT NOT NULL,
    applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
)`

type migration struct {
	version int
	name    string
	sql     string
}

// IsCurrent returns nil when every embedded migration is recorded in
// schema_migrations, checked per version the same way Migrate applies them.
// Versions recorded in the database but not embedded (a newer database read
// by an older binary) are ignored. When the unapplied versions all sit above
// the highest applied one it returns
//
//	schema version X, expected Y; run `tempogate migrate`
//
// and when any lies below it (migrations merged out of numeric order) it
// names them instead:
//
//	schema is missing migrations 10, 12; run `tempogate migrate`
//
// serve surfaces either message to the operator.
func (s *Store) IsCurrent(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, schemaVersionDDL); err != nil {
		return s.fail("is_current", fmt.Errorf("sqlite: ensure schema_migrations: %w", err))
	}

	migs, err := loadMigrations()
	if err != nil {
		return err
	}

	applied, err := loadAppliedVersions(ctx, s.db)
	if err != nil {
		return s.fail("is_current", err)
	}

	dbMax := 0
	for v := range applied {
		dbMax = max(dbMax, v)
	}

	var missing []string
	gap := false
	for _, m := range migs {
		if _, ok := applied[m.version]; ok {
			continue
		}
		missing = append(missing, strconv.Itoa(m.version))
		gap = gap || m.version < dbMax
	}

	switch {
	case len(missing) == 0:
		return nil
	case gap:
		return fmt.Errorf("schema is missing migrations %s; run `tempogate migrate`", strings.Join(missing, ", "))
	default:
		return fmt.Errorf("schema version %d, expected %d; run `tempogate migrate`", dbMax, migs[len(migs)-1].version)
	}
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

	for _, m := range migs {
		if _, ok := applied[m.version]; ok {
			continue
		}
		if err := applyMigration(ctx, s.db, m); err != nil {
			return err
		}
	}
	return nil
}

func loadMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("sqlite: read embed: %w", err)
	}

	out := make([]migration, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		m, err := parseMigration(e.Name())
		if err != nil {
			return nil, err
		}
		body, err := fs.ReadFile(migrationsFS, "migrations/"+e.Name())
		if err != nil {
			return nil, fmt.Errorf("sqlite: read %s: %w", e.Name(), err)
		}
		m.sql = string(body)
		out = append(out, m)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out, nil
}

func parseMigration(fname string) (migration, error) {
	base := strings.TrimSuffix(fname, ".sql")
	idx := strings.IndexByte(base, '_')
	if idx <= 0 {
		return migration{}, fmt.Errorf("sqlite: invalid migration filename %q (want NNNN_name.sql)", fname)
	}
	v, err := strconv.Atoi(base[:idx])
	if err != nil {
		return migration{}, fmt.Errorf("sqlite: invalid version in %q: %w", fname, err)
	}
	return migration{version: v, name: base[idx+1:]}, nil
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

func applyMigration(ctx context.Context, db *sql.DB, m migration) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlite: begin tx for %d_%s: %w", m.version, m.name, err)
	}
	if _, err := tx.ExecContext(ctx, m.sql); err != nil {
		return errors.Join(
			fmt.Errorf("sqlite: apply %d_%s: %w", m.version, m.name, err),
			tx.Rollback(),
		)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations (version, name) VALUES (?, ?)`,
		m.version, m.name,
	); err != nil {
		return errors.Join(
			fmt.Errorf("sqlite: record %d_%s: %w", m.version, m.name, err),
			tx.Rollback(),
		)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlite: commit %d_%s: %w", m.version, m.name, err)
	}
	return nil
}
