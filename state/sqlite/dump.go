package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// DumpTables calls visit once per table, in name order, with its column
// names and every row, for `tempogate state copy`. Values are as the driver
// returns them (time.Time for TIMESTAMP columns, []byte, string, int64 or
// nil); secrets are already stored as their SHA-256, so a row needs no
// re-encoding. schema_migrations is left out: the target records its own
// migrations.
//
// Everything is read in one transaction, so a copy taken while another
// process writes is still one consistent snapshot. visit runs inside it and
// may hold the rows only until it returns.
func (s *Store) DumpTables(ctx context.Context, visit func(table string, columns []string, rows [][]any) error) error {
	ctx, op := s.ops.Start(ctx, "dump_tables")
	defer op.End()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return op.Fail(fmt.Errorf("sqlite: begin dump: %w", err))
	}
	defer func() { _ = tx.Rollback() }()

	_, names, err := queryAll(ctx, tx,
		`SELECT name FROM sqlite_schema
		 WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name != 'schema_migrations'
		 ORDER BY name`)
	if err != nil {
		return op.Fail(fmt.Errorf("sqlite: list tables: %w", err))
	}
	for _, name := range names {
		table, _ := name[0].(string)
		// table comes from sqlite_schema, not from input; quoting keeps an
		// odd name from being read as SQL all the same.
		columns, rows, err := queryAll(ctx, tx, `SELECT * FROM "`+strings.ReplaceAll(table, `"`, `""`)+`"`) // #nosec G202 -- a quoted name from sqlite_schema.
		if err != nil {
			return op.Fail(fmt.Errorf("sqlite: read %s: %w", table, err))
		}
		if err := visit(table, columns, rows); err != nil {
			return err
		}
	}
	return nil
}

// queryAll runs query in tx and returns its column names and every row.
func queryAll(ctx context.Context, tx *sql.Tx, query string) ([]string, [][]any, error) {
	rows, err := tx.QueryContext(ctx, query)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = rows.Close() }()
	columns, err := rows.Columns()
	if err != nil {
		return nil, nil, err
	}
	var out [][]any
	for rows.Next() {
		row := make([]any, len(columns))
		ptrs := make([]any, len(columns))
		for i := range row {
			ptrs[i] = &row[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, nil, err
		}
		out = append(out, row)
	}
	return columns, out, rows.Err()
}
