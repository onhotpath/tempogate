package postgres

import (
	"fmt"
	"io/fs"
	"os"
	"strings"
	"sync"
	"testing"
	"testing/fstest"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/onhotpath/tempogate/state/internal/migration"
)

// withMigrations replaces the embedded migrations.
func withMigrations(fsys fs.FS) Option { return func(o *options) { o.migrations = fsys } }

// TestMigrationsPairWithSQLite holds the two directories together: Postgres
// starts at a baseline numbered like the SQLite migration it equals, and
// every later version exists in both, under the same name.
func TestMigrationsPairWithSQLite(t *testing.T) {
	pg, err := migration.Load(migrationsFS, "migrations", "postgres")
	require.NoError(t, err)
	lite, err := migration.Load(os.DirFS("../sqlite"), "migrations", "sqlite")
	require.NoError(t, err)

	baseline := pg[0]
	require.Equal(t, "baseline", baseline.Name, "the first Postgres migration is the baseline")
	names := func(migs []migration.Migration) map[int]string {
		out := map[int]string{}
		for _, m := range migs {
			if m.Version > baseline.Version {
				out[m.Version] = m.Name
			}
		}
		return out
	}
	require.Contains(t, names(lite), baseline.Version+1, "the baseline is not the SQLite head")
	require.Equal(t, names(lite), names(pg), "every migration after the baseline is a pair")
	require.LessOrEqual(t, baseline.Version, lite[len(lite)-1].Version)
}

func TestMigrate(t *testing.T) {
	forEachServer(t, func(t *testing.T, srv testServer) {
		t.Run("AnEmptyDatabaseIsVersionZero", func(t *testing.T) {
			s := newUnmigratedStore(t, srv)
			migs, err := s.loadMigrations()
			require.NoError(t, err)
			require.EqualError(t, s.IsCurrent(t.Context()),
				fmt.Sprintf("schema version 0, expected %d; run `tempogate migrate`", migs[len(migs)-1].Version))
			require.Error(t, s.Probe(t.Context()), "an unmigrated database is not ready")
		})

		t.Run("IsIdempotentAndRecordsEveryVersion", func(t *testing.T) {
			s := newTestStore(t, srv)
			require.NoError(t, s.Migrate(t.Context()))
			require.NoError(t, s.IsCurrent(t.Context()))
			require.NoError(t, s.Ping(t.Context()))
			require.NoError(t, s.Probe(t.Context()))

			migs, err := s.loadMigrations()
			require.NoError(t, err)
			var n int
			require.NoError(t, s.pool.QueryRow(t.Context(),
				`SELECT count(*) FROM schema_migrations WHERE applied_at IS NOT NULL`).Scan(&n))
			require.Equal(t, len(migs), n)
		})

		t.Run("ConcurrentRunsApplyEachVersionOnce", func(t *testing.T) {
			dsn := newDatabase(t, srv)
			var wg sync.WaitGroup
			errs := make([]error, 3)
			for i := range errs {
				s, err := New(WithDSN(dsn))
				require.NoError(t, err)
				t.Cleanup(func() { require.NoError(t, s.Close()) })
				wg.Go(func() { errs[i] = s.Migrate(t.Context()) })
			}
			wg.Wait()
			for _, err := range errs {
				require.NoError(t, err)
			}

			s := newStoreOn(t, dsn)
			require.NoError(t, s.IsCurrent(t.Context()))
			rows, err := s.pool.Query(t.Context(), `SELECT count(*) FROM schema_migrations GROUP BY version`)
			require.NoError(t, err)
			counts, err := pgx.CollectRows(rows, pgx.RowTo[int])
			require.NoError(t, err)
			require.NotEmpty(t, counts)
			for _, c := range counts {
				require.Equal(t, 1, c)
			}
		})

		t.Run("AFailingMigrationRollsBackCompletely", func(t *testing.T) {
			fsys := fstest.MapFS{
				"migrations/0001_good.sql":   {Data: []byte(`CREATE TABLE good (id INT); INSERT INTO good VALUES (1);`)},
				"migrations/0002_broken.sql": {Data: []byte(`CREATE TABLE half (id INT); SELECT 1/0;`)},
			}
			s := newUnmigratedStore(t, srv, withMigrations(fsys))
			require.ErrorContains(t, s.Migrate(t.Context()), "postgres: apply 2_broken: ")

			var leftovers int
			require.NoError(t, s.pool.QueryRow(t.Context(),
				`SELECT count(*) FROM pg_tables WHERE schemaname = 'public'`).Scan(&leftovers))
			require.Zero(t, leftovers, "nothing of the run survives, schema_migrations included")
		})

		t.Run("GapsAreNamedAndFilled", func(t *testing.T) {
			file := func(sql string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(sql)} }
			dsn := newDatabase(t, srv)
			older := newStoreOn(t, dsn, withMigrations(fstest.MapFS{
				"migrations/0001_a.sql": file(`CREATE TABLE a (id INT)`),
				"migrations/0003_c.sql": file(`CREATE TABLE c (id INT)`),
			}))
			require.NoError(t, older.Migrate(t.Context()))

			// A migration merged out of numeric order.
			newer := newStoreOn(t, dsn, withMigrations(fstest.MapFS{
				"migrations/0001_a.sql": file(`CREATE TABLE a (id INT)`),
				"migrations/0002_b.sql": file(`CREATE TABLE b (id INT)`),
				"migrations/0003_c.sql": file(`CREATE TABLE c (id INT)`),
				"migrations/0004_d.sql": file(`CREATE TABLE d (id INT)`),
			}))
			require.EqualError(t, newer.IsCurrent(t.Context()), "schema is missing migrations 2, 4; run `tempogate migrate`")
			require.NoError(t, newer.Migrate(t.Context()))
			require.NoError(t, newer.IsCurrent(t.Context()))
			require.NoError(t, older.IsCurrent(t.Context()), "versions this binary does not know are ignored")
		})

		t.Run("ABadMigrationFileFailsBeforeTouchingTheDatabase", func(t *testing.T) {
			s := newUnmigratedStore(t, srv, withMigrations(fstest.MapFS{"migrations/oops.sql": {}}))
			require.ErrorContains(t, s.Migrate(t.Context()), `postgres: invalid migration filename "oops.sql"`)
			require.ErrorContains(t, s.IsCurrent(t.Context()), `postgres: invalid migration filename "oops.sql"`)
		})
	})
}

// newStoreOn opens a store on an existing database, closed when t ends.
func newStoreOn(t *testing.T, dsn string, opts ...Option) *Store {
	t.Helper()
	s, err := New(append([]Option{WithDSN(dsn)}, opts...)...)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	return s
}

// TestCITestsTheImagesLocalRunsStart keeps CI's service containers and
// testImages on the same PostgreSQL builds, so local runs and CI agree.
func TestCITestsTheImagesLocalRunsStart(t *testing.T) {
	ci, err := os.ReadFile("../../.github/workflows/ci.yml")
	require.NoError(t, err)
	var services []string
	for line := range strings.Lines(string(ci)) {
		if image, ok := strings.CutPrefix(strings.TrimSpace(line), "image: postgres:"); ok {
			services = append(services, "postgres:"+image)
		}
	}
	require.ElementsMatch(t, testImages, services)
}
