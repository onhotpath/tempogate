package storetest

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func timeCases() []testCase {
	return []testCase{
		{"Time/PrecisionIsKeptToTheMicrosecond", func(t *testing.T, b Backend) {
			// Postgres timestamptz keeps microseconds; SQLite keeps the
			// nanoseconds Go writes. Either is fine, coarser is not.
			sub := t0.Add(789 * time.Nanosecond)
			saveKeypairs(t, b.Store, keypair("kid-1", sub))
			kps, err := b.Store.LoadKeypairs(t.Context())
			require.NoError(t, err)
			requireTime(t, sub, kps[0].CreatedAt, "created_at")
		}},
	}
}

// sqlClock matches SQL that reads the database's clock instead of a bound
// parameter, in either dialect: Postgres now() and friends, the standard
// CURRENT_* keywords, and SQLite's date functions and 'now' argument.
var sqlClock = regexp.MustCompile(`(?i)` +
	`\b(now|clock_timestamp|statement_timestamp|transaction_timestamp|timeofday|datetime|julianday|strftime|unixepoch|date|time)\s*\(` +
	`|\b(current_timestamp|current_date|current_time|localtimestamp|localtime)\b` +
	`|'now'`)

// CheckNoSQLClock enforces the rule that the application owns the clock
// (state/doc.go) on a backend's source: no SQL in its non-test Go files or
// its .sql migrations may read the database clock. fsys is the backend's
// package directory, migrations included.
func CheckNoSQLClock(t *testing.T, fsys fs.FS) {
	t.Helper()
	uses, err := sqlClockUses(fsys)
	require.NoError(t, err)
	for _, u := range uses {
		t.Errorf("SQL reads the database clock, bind the application's time instead: %s", u)
	}
}

// sqlClockUses lists every database-clock read in fsys as "file: match".
// Go files contribute their string literals, where SQL lives; .sql files
// their text without -- comments.
func sqlClockUses(fsys fs.FS) ([]string, error) {
	var uses []string
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		var texts []string
		switch {
		case strings.HasSuffix(p, "_test.go"):
			return nil
		case path.Ext(p) == ".go":
			texts, err = goStrings(fsys, p)
		case path.Ext(p) == ".sql":
			texts, err = sqlText(fsys, p)
		}
		if err != nil {
			return err
		}
		for _, text := range texts {
			for _, m := range sqlClock.FindAllString(text, -1) {
				uses = append(uses, fmt.Sprintf("%s: %s", p, m))
			}
		}
		return nil
	})
	return uses, err
}

func goStrings(fsys fs.FS, p string) ([]string, error) {
	src, err := fs.ReadFile(fsys, p)
	if err != nil {
		return nil, err
	}
	f, err := parser.ParseFile(token.NewFileSet(), p, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.ImportSpec:
			return false
		case *ast.BasicLit:
			if n.Kind == token.STRING {
				if s, err := strconv.Unquote(n.Value); err == nil {
					out = append(out, s)
				}
			}
		}
		return true
	})
	return out, nil
}

func sqlText(fsys fs.FS, p string) ([]string, error) {
	src, err := fs.ReadFile(fsys, p)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(src), "\n")
	for i, l := range lines {
		if j := strings.Index(l, "--"); j >= 0 {
			lines[i] = l[:j]
		}
	}
	return []string{strings.Join(lines, "\n")}, nil
}
