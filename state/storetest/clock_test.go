package storetest

import (
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/require"
)

func TestSQLClockUsesFindsEveryDialect(t *testing.T) {
	fsys := fstest.MapFS{
		"store.go": {Data: []byte(`package x

import "time"

const (
	stamp   = "UPDATE t SET at = CURRENT_TIMESTAMP WHERE id = ?"
	pg      = ` + "`SELECT now()`" + `
	lite    = "SELECT datetime('now')"
	clean   = "UPDATE t SET at = ? WHERE id = ?"
	message = "the time is now"
)

func f() time.Time { return time.Now() }
`)},
		"store_test.go":         {Data: []byte(`package x; const q = "SELECT now()"`)},
		"migrations/0001_t.sql": {Data: []byte("-- do not use now() here\nCREATE TABLE t (at TIMESTAMP NOT NULL DEFAULT localtimestamp);\n")},
		"migrations/0002_u.sql": {Data: []byte("CREATE TABLE u (at TIMESTAMP NOT NULL);\n")},
		"README.md":             {Data: []byte("now() is fine in prose")},
	}
	uses, err := sqlClockUses(fsys)
	require.NoError(t, err)
	require.Equal(t, []string{
		"migrations/0001_t.sql: localtimestamp",
		"store.go: CURRENT_TIMESTAMP",
		"store.go: now(",
		"store.go: datetime(",
		"store.go: 'now'",
	}, uses)
}

func TestSQLClockUsesReportsUnparsableGo(t *testing.T) {
	_, err := sqlClockUses(fstest.MapFS{"broken.go": {Data: []byte("package")}})
	require.Error(t, err)
}
