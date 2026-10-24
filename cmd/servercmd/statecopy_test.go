package servercmd

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/onhotpath/tempogate/keys"
	"github.com/onhotpath/tempogate/state/postgres"
	"github.com/onhotpath/tempogate/state/sqlite"
)

// fakeImporter records what `state copy` asks of the target. Import reads
// the source through, so a test sees what would have been copied.
type fakeImporter struct {
	calls  []string
	force  bool
	tables []string
	err    error
}

func (f *fakeImporter) Ping(context.Context) error {
	f.calls = append(f.calls, "ping")
	return nil
}

func (f *fakeImporter) Migrate(context.Context) error {
	f.calls = append(f.calls, "migrate")
	return nil
}

func (f *fakeImporter) Import(ctx context.Context, src postgres.Source, opts ...postgres.ImportOption) (map[string]int64, error) {
	f.calls = append(f.calls, "import")
	// ImportForce is the only option, and its effect is private to postgres.
	f.force = len(opts) > 0
	if f.err != nil {
		return nil, f.err
	}
	copied := map[string]int64{}
	err := src.DumpTables(ctx, func(table string, _ []string, rows [][]any) error {
		f.tables = append(f.tables, table)
		copied[table] = int64(len(rows))
		return nil
	})
	return copied, err
}

// migratedSQLite returns the path of a migrated SQLite store holding one
// keypair.
func migratedSQLite(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := sqlite.New(sqlite.WithPath(path))
	require.NoError(t, err)
	require.NoError(t, s.Migrate(t.Context()))
	require.NoError(t, s.SaveKeypair(t.Context(), keys.Keypair{
		Kid: "kid-1", Alg: "RS256", PrivatePEM: []byte("p"), PublicPEM: []byte("p"), CreatedAt: time.Now().UTC(),
	}))
	require.NoError(t, s.Close())
	return path
}

func runStateCopy(t *testing.T, target stateImporter, sqlitePath string, args ...string) (string, error) {
	t.Helper()
	out := &bytes.Buffer{}
	c := newStateCmd(supply(stateCopyParams{
		Logger: zap.NewNop(), Target: target, SqlitePath: sqlitePath, SqliteBusyTimeout: time.Second,
	}))
	c.SetArgs(append([]string{"copy"}, args...))
	c.SetOut(out)
	c.SetErr(out)
	err := c.ExecuteContext(t.Context())
	return out.String(), err
}

func TestStateCopy(t *testing.T) {
	t.Run("copies STATE_SQLITE_PATH into the migrated target", func(t *testing.T) {
		target := &fakeImporter{}
		out, err := runStateCopy(t, target, migratedSQLite(t))
		require.NoError(t, err)
		require.Equal(t, []string{"ping", "migrate", "import"}, target.calls)
		require.False(t, target.force)
		require.Contains(t, target.tables, "keypairs")
		require.NotContains(t, target.tables, "schema_migrations", "the target records its own migrations")
		require.Contains(t, out, "keypairs: 1 rows\n")
		require.Contains(t, out, "set STATE_DRIVER=postgres")
	})

	t.Run("--from overrides STATE_SQLITE_PATH and --force passes through", func(t *testing.T) {
		target := &fakeImporter{}
		_, err := runStateCopy(t, target, filepath.Join(t.TempDir(), "absent.db"), "--from", migratedSQLite(t), "--force")
		require.NoError(t, err)
		require.True(t, target.force)
	})

	t.Run("a missing source is not created", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "absent.db")
		target := &fakeImporter{}
		_, err := runStateCopy(t, target, path)
		require.ErrorContains(t, err, "source "+path+" does not exist")
		require.NoFileExists(t, path)
		require.Empty(t, target.calls, "the target is not touched")
	})

	t.Run("an unmigrated source is refused", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "old.db")
		s, err := sqlite.New(sqlite.WithPath(path))
		require.NoError(t, err)
		require.NoError(t, s.Close())
		target := &fakeImporter{}
		_, err = runStateCopy(t, target, path)
		require.ErrorContains(t, err, "run `tempogate migrate` against it with STATE_DRIVER=sqlite first")
		require.Empty(t, target.calls)
	})

	t.Run("a target holding state names --force", func(t *testing.T) {
		target := &fakeImporter{err: postgres.ErrTargetNotEmpty}
		_, err := runStateCopy(t, target, migratedSQLite(t))
		require.ErrorIs(t, err, postgres.ErrTargetNotEmpty)
		require.ErrorContains(t, err, "pass --force to replace it")
	})
}

// The real wiring builds the Postgres target from STATE_POSTGRES_* while
// STATE_DRIVER still says sqlite, as it does before the switch.
func TestStateCopyBuildsPostgresWhateverTheDriver(t *testing.T) {
	t.Setenv("STATE_DRIVER", "sqlite")
	t.Setenv("STATE_SQLITE_PATH", migratedSQLite(t))
	t.Setenv("STATE_POSTGRES_DSN", "postgres://tempogate@127.0.0.1:1/tempogate?connect_timeout=2")
	require.ErrorContains(t, runCmd(fxCommands(t)["state"], "copy"), "target unreachable: postgres: ping: ")
}
