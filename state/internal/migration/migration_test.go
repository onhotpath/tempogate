package migration

import (
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	cases := []struct {
		name    string
		fname   string
		wantErr string
		wantVer int
	}{
		{"valid", "0001_keypairs.sql", "", 1},
		{"three digits", "042_foo.sql", "", 42},
		{"no underscore", "0001.sql", `sqlite: invalid migration filename "0001.sql" (want NNNN_name.sql)`, 0},
		{"underscore at start", "_keypairs.sql", `sqlite: invalid migration filename "_keypairs.sql"`, 0},
		{"non-numeric prefix", "abcd_foo.sql", `sqlite: invalid version in "abcd_foo.sql"`, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := parse(tc.fname, "sqlite")
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.wantVer, m.Version)
		})
	}
}

func TestLoadOrdersByVersionAndSkipsOtherFiles(t *testing.T) {
	fsys := fstest.MapFS{
		"migrations/0010_ten.sql":   {Data: []byte("ten")},
		"migrations/0002_two.sql":   {Data: []byte("two")},
		"migrations/README.md":      {Data: []byte("not a migration")},
		"migrations/sub/0001_x.sql": {Data: []byte("nested")},
	}
	migs, err := Load(fsys, "migrations", "postgres")
	require.NoError(t, err)
	require.Equal(t, []Migration{{2, "two", "two"}, {10, "ten", "ten"}}, migs)
}

func TestLoadPrefixesErrorsWithTheBackend(t *testing.T) {
	_, err := Load(fstest.MapFS{}, "migrations", "postgres")
	require.ErrorContains(t, err, "postgres: read embed: ")

	_, err = Load(fstest.MapFS{"migrations/x.sql": {}}, "migrations", "postgres")
	require.ErrorContains(t, err, `postgres: invalid migration filename "x.sql"`)
}

func TestCheck(t *testing.T) {
	migs := []Migration{{Version: 1}, {Version: 2}, {Version: 3}, {Version: 5}}
	applied := func(vs ...int) map[int]struct{} {
		out := map[int]struct{}{}
		for _, v := range vs {
			out[v] = struct{}{}
		}
		return out
	}

	require.NoError(t, Check(migs, applied(1, 2, 3, 5)))
	require.NoError(t, Check(migs, applied(1, 2, 3, 5, 999)), "a newer database is not this binary's concern")
	require.EqualError(t, Check(migs, applied()),
		"schema version 0, expected 5; run `tempogate migrate`")
	require.EqualError(t, Check(migs, applied(1, 2)),
		"schema version 2, expected 5; run `tempogate migrate`")
	require.EqualError(t, Check(migs, applied(1, 3, 5)),
		"schema is missing migrations 2; run `tempogate migrate`")
	require.EqualError(t, Check(migs, applied(1, 3)),
		"schema is missing migrations 2, 5; run `tempogate migrate`", "a gap names every missing version")
}

func TestPending(t *testing.T) {
	migs := []Migration{{Version: 1}, {Version: 2}, {Version: 3}}
	require.Equal(t, []Migration{{Version: 1}, {Version: 3}}, Pending(migs, map[int]struct{}{2: {}}))
	require.Empty(t, Pending(migs, map[int]struct{}{1: {}, 2: {}, 3: {}}))
}
