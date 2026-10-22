package postgres

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/onhotpath/tempogate/state/storetest"
)

// newTestStore returns a store over a fresh, migrated database on srv,
// closed when t ends.
func newTestStore(t testing.TB, srv testServer, opts ...Option) *Store {
	t.Helper()
	s := newUnmigratedStore(t, srv, opts...)
	require.NoError(t, s.Migrate(t.Context()))
	return s
}

// newUnmigratedStore is newTestStore without the migration.
func newUnmigratedStore(t testing.TB, srv testServer, opts ...Option) *Store {
	t.Helper()
	s, err := New(append([]Option{WithDSN(newDatabase(t, srv))}, opts...)...)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	return s
}

// forEachServer runs fn as a subtest per server under test.
func forEachServer(t *testing.T, fn func(t *testing.T, srv testServer)) {
	t.Helper()
	for _, srv := range testServers(t) {
		t.Run(srv.Name, func(t *testing.T) { fn(t, srv) })
	}
}

// TestConformance runs the state contract's suite against every server,
// wired the way Fx binds the store.
func TestConformance(t *testing.T) {
	forEachServer(t, func(t *testing.T, srv testServer) {
		storetest.Run(t, func(t *testing.T) storetest.Backend {
			s := newTestStore(t, srv)
			return storetest.Backend{
				Store:       s,
				KeyRegistry: NewAdminKeyRegistry(s),
				Sessions:    NewAdminSessionStore(s),
				Changes:     s,
			}
		})
	})
}

func TestNeverReadsTheDatabaseClock(t *testing.T) {
	storetest.CheckNoSQLClock(t, os.DirFS("."))
}
