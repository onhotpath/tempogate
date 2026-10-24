package postgres

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/onhotpath/tempogate/keys"
)

// ErrTargetNotEmpty is returned by Import when the database already holds
// state and ImportForce was not given.
var ErrTargetNotEmpty = errors.New("postgres: target database already holds state")

// Source is a state store Import copies from: `tempogate state copy` passes
// a *sqlite.Store. DumpTables calls visit once per table with its column
// names and every row, from one consistent snapshot, leaving out the
// migrations table.
type Source interface {
	DumpTables(ctx context.Context, visit func(table string, columns []string, rows [][]any) error) error
}

type importOptions struct {
	force bool
}

type ImportOption func(*importOptions)

// ImportForce replaces whatever state the database holds instead of
// refusing it with ErrTargetNotEmpty. The old rows are deleted in the same
// transaction that writes the new ones, so a failed import leaves them.
func ImportForce() ImportOption { return func(o *importOptions) { o.force = true } }

// derivedTables are the tables only Postgres has, with the statement that
// rebuilds each from the imported rows. refresh_families is the row lock
// SQLite's single writer does not need (migration 0015); its revoked_at is
// what SQLite reads off the family's tokens, as the migration backfills it.
var derivedTables = map[string]string{
	"refresh_families": `INSERT INTO refresh_families (family_id, revoked_at)
		SELECT family_id, min(revoked_at) FROM refresh_tokens GROUP BY family_id`,
}

// importLockTimeout bounds the wait for the table locks Import takes, so a
// copy run against a database still serving fails instead of stalling it.
const importLockTimeout = "5s"

// Import copies every table src holds into this database, in one
// transaction, and returns the number of rows written per table. The
// database must be migrated to the same schema as src: every table and
// column of each side must exist on the other, except derivedTables, which
// are rebuilt, so a column a future migration adds cannot be dropped
// silently. A database that already holds state is refused with
// ErrTargetNotEmpty unless ImportForce.
//
// Every table is locked ACCESS EXCLUSIVE for the copy, so no replica writes
// in between; run it with every replica stopped all the same, as a replica
// writing to the source after the copy loses that write. Errors name tables,
// columns and Go types, never a value: rows hold signing keys and token
// hashes.
func (s *Store) Import(ctx context.Context, src Source, opts ...ImportOption) (map[string]int64, error) {
	o := &importOptions{}
	for _, opt := range opts {
		opt(o)
	}
	ctx, op := s.ops.Start(ctx, "import")
	defer op.End()

	var copied map[string]int64
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		target, err := targetColumns(ctx, tx)
		if err != nil {
			return err
		}
		tables := slices.Sorted(maps.Keys(target))
		if err := lockForImport(ctx, tx, tables); err != nil {
			return err
		}
		if err := clearForImport(ctx, tx, tables, o.force); err != nil {
			return err
		}

		copied = make(map[string]int64, len(tables))
		err = src.DumpTables(ctx, func(table string, columns []string, rows [][]any) error {
			if _, derived := derivedTables[table]; derived {
				return fmt.Errorf("postgres: import: source table %s is one this database derives", table)
			}
			types, ok := target[table]
			if !ok {
				return fmt.Errorf("postgres: import: source table %s has no counterpart here; migrate both to the same release", table)
			}
			n, err := copyTable(ctx, tx, table, columns, types, rows)
			if err != nil {
				return err
			}
			copied[table] = n
			return nil
		})
		if err != nil {
			return err
		}
		for _, table := range tables {
			if _, derived := derivedTables[table]; derived {
				continue
			}
			if _, ok := copied[table]; !ok {
				return fmt.Errorf("postgres: import: table %s is missing from the source; migrate both to the same release", table)
			}
		}
		for table, stmt := range derivedTables {
			tag, err := tx.Exec(ctx, stmt)
			if err != nil {
				return fmt.Errorf("postgres: import: rebuild %s: %w", table, err)
			}
			copied[table] = tag.RowsAffected()
		}
		// Replicas left running reload keys now rather than at their next
		// KEYS_RELOAD_INTERVAL.
		return notify(ctx, tx, keys.Change{Kind: keys.ChangeKeys})
	})
	if err != nil {
		return nil, op.Fail(err)
	}
	return copied, nil
}

// targetColumns returns each table of the current schema, but
// schema_migrations, with its columns' data types by name.
func targetColumns(ctx context.Context, tx pgx.Tx) (map[string]map[string]string, error) {
	// ForEachRow reports a failed Query too.
	rows, _ := tx.Query(ctx,
		`SELECT c.table_name, c.column_name, c.data_type
		 FROM information_schema.columns c
		 JOIN information_schema.tables t
		   ON t.table_schema = c.table_schema AND t.table_name = c.table_name
		 WHERE c.table_schema = current_schema() AND t.table_type = 'BASE TABLE'
		   AND c.table_name != 'schema_migrations'`)
	out := map[string]map[string]string{}
	var table, column, dataType string
	_, err := pgx.ForEachRow(rows, []any{&table, &column, &dataType}, func() error {
		if out[table] == nil {
			out[table] = map[string]string{}
		}
		out[table][column] = dataType
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("postgres: import: read schema: %w", err)
	}
	if len(out) == 0 {
		return nil, errors.New("postgres: import: the database has no tables; migrate it first")
	}
	return out, nil
}

func lockForImport(ctx context.Context, tx pgx.Tx, tables []string) error {
	// Without arguments pgx sends both statements in one simple-protocol
	// round trip; SET LOCAL ends with the transaction.
	if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout = '`+importLockTimeout+`'; `+
		`LOCK TABLE `+identifiers(tables)+` IN ACCESS EXCLUSIVE MODE`); err != nil {
		return fmt.Errorf("postgres: import: lock tables (stop every replica first): %w", err)
	}
	return nil
}

// clearForImport refuses a database that holds any row, or with force
// deletes every row.
func clearForImport(ctx context.Context, tx pgx.Tx, tables []string, force bool) error {
	for _, table := range tables {
		ident := pgx.Identifier{table}.Sanitize()
		if force {
			if _, err := tx.Exec(ctx, `DELETE FROM `+ident); err != nil {
				return fmt.Errorf("postgres: import: clear %s: %w", table, err)
			}
			continue
		}
		var held bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM `+ident+`)`).Scan(&held); err != nil {
			return fmt.Errorf("postgres: import: check %s: %w", table, err)
		}
		if held {
			return fmt.Errorf("%w (table %s has rows)", ErrTargetNotEmpty, table)
		}
	}
	return nil
}

func identifiers(names []string) string {
	quoted := make([]string, len(names))
	for i, n := range names {
		quoted[i] = pgx.Identifier{n}.Sanitize()
	}
	return strings.Join(quoted, ", ")
}

// copyTable writes rows into table with COPY, after checking that columns
// name exactly the table's columns and converting each value to the
// column's type.
func copyTable(ctx context.Context, tx pgx.Tx, table string, columns []string, types map[string]string, rows [][]any) (int64, error) {
	for _, c := range columns {
		if _, ok := types[c]; !ok {
			return 0, fmt.Errorf("postgres: import: source column %s.%s has no counterpart here; migrate both to the same release", table, c)
		}
	}
	if len(columns) != len(types) {
		for c := range types {
			if !slices.Contains(columns, c) {
				return 0, fmt.Errorf("postgres: import: column %s.%s is missing from the source; migrate both to the same release", table, c)
			}
		}
	}
	for _, row := range rows {
		if len(row) != len(columns) {
			return 0, fmt.Errorf("postgres: import: a %s row has %d values for %d columns", table, len(row), len(columns))
		}
		for i, v := range row {
			cv, err := importValue(v, types[columns[i]])
			if err != nil {
				return 0, fmt.Errorf("postgres: import: %s.%s: %w", table, columns[i], err)
			}
			row[i] = cv
		}
	}
	n, err := tx.CopyFrom(ctx, pgx.Identifier{table}, columns, pgx.CopyFromRows(rows))
	if err != nil {
		return 0, fmt.Errorf("postgres: import: copy %s: %w", table, err)
	}
	return n, nil
}

// sqliteTimeLayouts are the text forms a SQLite TIMESTAMP may hold that its
// driver did not already parse: what the driver writes (time.Time.String,
// monotonic reading stripped) and what SQL literals and older defaults
// wrote, such as migration 0011's '1970-01-01 00:00:00'.
var sqliteTimeLayouts = []string{
	"2006-01-02 15:04:05.999999999 -0700 MST",
	"2006-01-02 15:04:05.999999999-07:00",
	"2006-01-02T15:04:05.999999999-07:00",
	"2006-01-02 15:04:05.999999999",
	"2006-01-02T15:04:05.999999999",
	"2006-01-02 15:04:05",
	"2006-01-02T15:04:05",
	"2006-01-02",
}

// importValue converts v, as a source driver returned it, to what COPY
// writes into a column of dataType. An unknown type fails, so a column type
// a future migration introduces gets a deliberate conversion here. Errors
// carry the Go type only: v may be a secret.
func importValue(v any, dataType string) (any, error) {
	if v == nil {
		return nil, nil
	}
	switch dataType {
	case "text":
		switch x := v.(type) {
		case string:
			return x, nil
		case []byte:
			return string(x), nil
		}
	case "bytea":
		switch x := v.(type) {
		case []byte:
			return x, nil
		case string:
			return []byte(x), nil
		}
	case "integer", "bigint", "smallint":
		if x, ok := v.(int64); ok {
			return x, nil
		}
	case "timestamp with time zone":
		switch x := v.(type) {
		case time.Time:
			// The contract keeps microseconds (state/doc.go); Postgres would
			// round a finer value, so truncate as the application clock does.
			return x.UTC().Truncate(time.Microsecond), nil
		case string:
			s, _, _ := strings.Cut(x, " m=")
			for _, layout := range sqliteTimeLayouts {
				if t, err := time.Parse(layout, s); err == nil {
					return t.UTC().Truncate(time.Microsecond), nil
				}
			}
			return nil, errors.New("text value is not a timestamp")
		}
	default:
		return nil, fmt.Errorf("no conversion for column type %q", dataType)
	}
	return nil, fmt.Errorf("cannot store a %T in a column of type %s", v, dataType)
}
