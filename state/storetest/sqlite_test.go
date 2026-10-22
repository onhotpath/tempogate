package storetest_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/onhotpath/tempogate/state/sqlite"
	"github.com/onhotpath/tempogate/state/storetest"
)

// TestSQLite runs the conformance suite against the default backend, wired
// the way sqlite.Fx binds it.
func TestSQLite(t *testing.T) {
	storetest.Run(t, func(t *testing.T) storetest.Backend {
		s, err := sqlite.New(sqlite.WithPath(filepath.Join(t.TempDir(), "state.db")), sqlite.WithBusyTimeout(5*time.Second))
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, s.Close()) })
		require.NoError(t, s.Migrate(t.Context()))
		return storetest.Backend{
			Store:       s,
			KeyRegistry: sqlite.NewAdminKeyRegistry(s),
			Sessions:    sqlite.NewAdminSessionStore(s),
			Changes:     s,
		}
	})
}

func TestSQLiteNeverReadsTheDatabaseClock(t *testing.T) {
	storetest.CheckNoSQLClock(t, os.DirFS("../sqlite"))
}
