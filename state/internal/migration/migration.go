// Package migration is the dialect-neutral half of the state backends'
// schema runners: reading the embedded NNNN_name.sql files, ordering them,
// and judging a database's recorded versions against them. Applying a
// migration, and the schema_migrations table that records it, stay in each
// backend (state/sqlite/migrate.go, state/postgres/migrate.go), because
// transactions and locking are what differ between dialects.
package migration

import (
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
)

// Migration is one embedded NNNN_name.sql file.
type Migration struct {
	Version int
	Name    string
	SQL     string
}

// Load reads every .sql file in dir of fsys, ordered by version. backend
// ("sqlite", "postgres") prefixes every error.
func Load(fsys fs.FS, dir, backend string) ([]Migration, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("%s: read embed: %w", backend, err)
	}

	out := make([]Migration, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		m, err := parse(e.Name(), backend)
		if err != nil {
			return nil, err
		}
		body, err := fs.ReadFile(fsys, path.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("%s: read %s: %w", backend, e.Name(), err)
		}
		m.SQL = string(body)
		out = append(out, m)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

func parse(fname, backend string) (Migration, error) {
	base := strings.TrimSuffix(fname, ".sql")
	idx := strings.IndexByte(base, '_')
	if idx <= 0 {
		return Migration{}, fmt.Errorf("%s: invalid migration filename %q (want NNNN_name.sql)", backend, fname)
	}
	v, err := strconv.Atoi(base[:idx])
	if err != nil {
		return Migration{}, fmt.Errorf("%s: invalid version in %q: %w", backend, fname, err)
	}
	return Migration{Version: v, Name: base[idx+1:]}, nil
}

// Pending returns the migrations in migs whose version is not in applied,
// in order.
func Pending(migs []Migration, applied map[int]struct{}) []Migration {
	var out []Migration
	for _, m := range migs {
		if _, ok := applied[m.Version]; !ok {
			out = append(out, m)
		}
	}
	return out
}

// Check returns nil when every migration in migs is in applied, checked per
// version the same way the runners apply them. Versions applied but not in
// migs (a newer database read by an older binary) are ignored. When the
// unapplied versions all sit above the highest applied one it returns
//
//	schema version X, expected Y; run `tempogate migrate`
//
// and when any lies below it (migrations merged out of numeric order) it
// names them instead:
//
//	schema is missing migrations 10, 12; run `tempogate migrate`
//
// serve surfaces either message to the operator.
func Check(migs []Migration, applied map[int]struct{}) error {
	dbMax := 0
	for v := range applied {
		dbMax = max(dbMax, v)
	}

	var missing []string
	gap := false
	for _, m := range Pending(migs, applied) {
		missing = append(missing, strconv.Itoa(m.Version))
		gap = gap || m.Version < dbMax
	}

	switch {
	case len(missing) == 0:
		return nil
	case gap:
		return fmt.Errorf("schema is missing migrations %s; run `tempogate migrate`", strings.Join(missing, ", "))
	default:
		return fmt.Errorf("schema version %d, expected %d; run `tempogate migrate`", dbMax, migs[len(migs)-1].Version)
	}
}
