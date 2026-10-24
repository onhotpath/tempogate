package postgres

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/onhotpath/tempogate/admin"
	"github.com/onhotpath/tempogate/keys"
	"github.com/onhotpath/tempogate/oidc"
	"github.com/onhotpath/tempogate/state/sqlite"
)

// importT0 carries microseconds, so a copy that loses precision or shifts
// the zone fails the round trip.
var importT0 = time.Date(2001, 2, 3, 4, 5, 6, 123456000, time.UTC)

// newSQLiteSource returns a migrated SQLite store holding a row in every
// table and a non-NULL value in every column across those rows, the way a
// release that ran for a while leaves it.
func newSQLiteSource(t *testing.T) *sqlite.Store {
	t.Helper()
	ctx := t.Context()
	src, err := sqlite.New(sqlite.WithPath(filepath.Join(t.TempDir(), "state.db")))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, src.Close()) })
	require.NoError(t, src.Migrate(ctx))

	at := importT0.Add
	for i, kid := range []string{"kid-old", "kid-new"} {
		require.NoError(t, src.SaveKeypair(ctx, keys.Keypair{
			Kid: kid, Alg: "RS256", PrivatePEM: []byte("private-" + kid), PublicPEM: []byte("public-" + kid),
			CreatedAt: at(time.Duration(i) * time.Hour),
		}))
	}
	_, err = src.RetireKeypair(ctx, "kid-old", at(2*time.Hour))
	require.NoError(t, err)

	require.NoError(t, src.SaveAuthRequest(ctx, oidc.AuthRequest{
		InternalState: "state-1", ConnectorID: "google", ClientID: "temporal-ui", RedirectURI: "https://ui/cb",
		Scope: "openid email", ClientState: "cs", CodeChallenge: "cc", CodeChallengeMethod: "S256", Nonce: "n",
		CreatedAt: at(0), ExpiresAt: at(10 * time.Minute),
	}))

	for _, code := range []string{"code-live", "code-used"} {
		require.NoError(t, src.SaveAuthCode(ctx, oidc.AuthCode{
			Code: code, ClientID: "temporal-ui", RedirectURI: "https://ui/cb", ConnectorID: "google",
			Subject: "sub-alice", Email: "alice@example.com", Scope: "openid", CodeChallenge: "cc",
			CodeChallengeMethod: "S256", Nonce: "n", CreatedAt: at(0), ExpiresAt: at(time.Minute),
		}))
	}
	_, err = src.ConsumeAuthCode(ctx, "code-used", "fam-live", at(time.Second))
	require.NoError(t, err)

	for _, r := range []struct{ token, family string }{
		{"rt-used", "fam-live"}, {"rt-live", "fam-live"}, {"rt-revoked", "fam-revoked"},
	} {
		require.NoError(t, src.SaveRefresh(ctx, oidc.Refresh{
			Token: r.token, JTI: "jti-" + r.token, ClientID: "tempogate-cli", ConnectorID: "google",
			Subject: "sub-alice", Email: "alice@example.com", FamilyID: r.family,
			AuthTime: at(0), CreatedAt: at(time.Second), ExpiresAt: at(24 * time.Hour),
		}))
	}
	_, err = src.ConsumeRefresh(ctx, "rt-used", "tempogate-cli", at(time.Minute))
	require.NoError(t, err)
	_, err = src.RevokeRefreshFamily(ctx, "fam-revoked", at(2*time.Minute))
	require.NoError(t, err)

	registry := sqlite.NewAdminKeyRegistry(src)
	exp := at(48 * time.Hour)
	for _, id := range []string{"0190a000-0000-7000-8000-000000000001", "0190a000-0000-7000-8000-000000000002"} {
		require.NoError(t, registry.Save(ctx, admin.IntegrationKey{
			ID: id, Namespace: "orders", Role: admin.RoleWorker, Owner: "alice@example.com",
			JTI: "jti-" + id, CreatedAt: at(0), ExpiresAt: &exp,
		}))
	}
	_, err = registry.MarkRevoked(ctx, "0190a000-0000-7000-8000-000000000001", at(3*time.Minute))
	require.NoError(t, err)

	for i, uc := range []string{"BCDFGHJK", "LMNPQRST"} {
		require.NoError(t, src.SaveDeviceCode(ctx, oidc.DeviceCode{
			Code: fmt.Sprintf("dc-%d", i), UserCode: uc, ClientID: "tempogate-device", Scope: "openid",
			IntervalSeconds: 5, CreatedAt: at(0), ExpiresAt: at(10 * time.Minute),
		}))
	}
	_, err = src.PollDeviceCode(ctx, "dc-0", at(time.Second))
	require.NoError(t, err)
	require.NoError(t, src.ApproveDeviceCode(ctx, "BCDFGHJK",
		oidc.Identity{ConnectorID: "google", Subject: "sub-alice", Email: "alice@example.com"}, at(2*time.Second)))
	require.NoError(t, src.DenyDeviceCode(ctx, "LMNPQRST", at(2*time.Second)))

	require.NoError(t, src.SaveBrowserSession(ctx, oidc.BrowserSession{
		SID: "sid-1", ConnectorID: "google", Subject: "sub-alice", Email: "alice@example.com",
		CreatedAt: at(0), ExpiresAt: at(5 * time.Minute),
	}))
	return src
}

// dumped is a store's tables as DumpTables reports them.
type dumped map[string]struct {
	columns []string
	rows    [][]any
}

func dumpOf(t *testing.T, src Source) dumped {
	t.Helper()
	out := dumped{}
	require.NoError(t, src.DumpTables(t.Context(), func(table string, columns []string, rows [][]any) error {
		out[table] = struct {
			columns []string
			rows    [][]any
		}{columns, rows}
		return nil
	}))
	return out
}

// targetRows reads table back from Postgres as column name to value, keyed
// by the first column (every table's primary key).
func targetRows(t *testing.T, s *Store, table string) map[any]map[string]any {
	t.Helper()
	rows, err := s.pool.Query(t.Context(), `SELECT * FROM `+pgx.Identifier{table}.Sanitize())
	require.NoError(t, err)
	maps, err := pgx.CollectRows(rows, pgx.RowToMap)
	require.NoError(t, err)
	out := map[any]map[string]any{}
	for _, m := range maps {
		out[fmt.Sprint(m[rows.FieldDescriptions()[0].Name])] = m
	}
	return out
}

// sameValue compares a source value with what Postgres returned for it.
func sameValue(t *testing.T, want, got any, what string) {
	t.Helper()
	switch w := want.(type) {
	case time.Time:
		g, ok := got.(time.Time)
		require.Truef(t, ok, "%s: got a %T", what, got)
		require.Truef(t, w.Equal(g), "%s: want %s, got %s", what, w, g)
	case int64:
		require.EqualValuesf(t, w, got, what)
	default:
		require.Equalf(t, want, got, what)
	}
}

// Every table and column of the SQLite schema arrives intact. The source
// is checked to fill every column, so a table or column a later migration
// adds fails here until newSQLiteSource writes it, and Import refuses a
// schema mismatch at run time either way.
func TestImportRoundTripsEveryTable(t *testing.T) {
	forEachServer(t, func(t *testing.T, srv testServer) {
		src := newSQLiteSource(t)
		dst := newTestStore(t, srv)
		want := dumpOf(t, src)

		for table, d := range want {
			require.NotEmptyf(t, d.rows, "newSQLiteSource writes no %s row", table)
			for i, c := range d.columns {
				filled := false
				for _, r := range d.rows {
					filled = filled || r[i] != nil
				}
				require.Truef(t, filled, "newSQLiteSource never fills %s.%s", table, c)
			}
		}

		copied, err := dst.Import(t.Context(), src)
		require.NoError(t, err)

		for table, d := range want {
			require.EqualValuesf(t, len(d.rows), copied[table], "%s rows reported", table)
			got := targetRows(t, dst, table)
			require.Lenf(t, got, len(d.rows), "%s rows", table)
			for _, r := range d.rows {
				g, ok := got[fmt.Sprint(r[0])]
				require.Truef(t, ok, "%s row missing", table)
				for i, c := range d.columns {
					sameValue(t, r[i], g[c], table+"."+c)
				}
			}
		}
		require.EqualValues(t, 2, copied["refresh_families"], "one family row per family")
	})
}

// The copy is usable as a store: tokens and sessions found by the raw
// values clients hold, revocations and the family lock carried over.
func TestImportedStateServes(t *testing.T) {
	forEachServer(t, func(t *testing.T, srv testServer) {
		ctx := t.Context()
		src := newSQLiteSource(t)
		dst := newTestStore(t, srv)
		_, err := dst.Import(ctx, src)
		require.NoError(t, err)

		kps, err := dst.LoadKeypairs(ctx)
		require.NoError(t, err)
		require.Len(t, kps, 2)
		require.NotNil(t, kps[0].RetiredAt, "kid-old stays retired")
		require.Equal(t, []byte("private-kid-new"), kps[1].PrivatePEM)

		rt, err := dst.ConsumeRefresh(ctx, "rt-live", "tempogate-cli", importT0.Add(time.Hour))
		require.NoError(t, err)
		require.Equal(t, "sub-alice", rt.Subject)
		_, err = dst.ConsumeRefresh(ctx, "rt-used", "tempogate-cli", importT0.Add(time.Hour))
		require.ErrorIs(t, err, oidc.ErrRefreshReused)
		err = dst.SaveRefresh(ctx, oidc.Refresh{
			Token: "rt-child", JTI: "jti-child", ClientID: "tempogate-cli", ConnectorID: "google",
			Subject: "sub-alice", Email: "alice@example.com", FamilyID: "fam-revoked",
			AuthTime: importT0, CreatedAt: importT0.Add(time.Hour), ExpiresAt: importT0.Add(2 * time.Hour),
		})
		require.ErrorIs(t, err, oidc.ErrRefreshFamilyRevoked, "the revoked family's lock row came along")

		revoked, err := dst.IsRevoked(ctx, "jti-0190a000-0000-7000-8000-000000000001")
		require.NoError(t, err)
		require.True(t, revoked)

		bs, err := dst.LookupBrowserSession(ctx, "sid-1")
		require.NoError(t, err)
		require.Equal(t, "alice@example.com", bs.Email)
		dc, err := dst.ConsumeDeviceCode(ctx, "dc-0")
		require.NoError(t, err)
		require.Equal(t, "google", dc.ConnectorID)
	})
}

func TestImportRefusesATargetWithStateUnlessForced(t *testing.T) {
	forEachServer(t, func(t *testing.T, srv testServer) {
		ctx := t.Context()
		src := newSQLiteSource(t)
		dst := newTestStore(t, srv)
		require.NoError(t, dst.SaveKeypair(ctx, keys.Keypair{
			Kid: "kid-target", Alg: "RS256", PrivatePEM: []byte("p"), PublicPEM: []byte("p"), CreatedAt: importT0,
		}))

		_, err := dst.Import(ctx, src)
		require.ErrorIs(t, err, ErrTargetNotEmpty)
		kps, err := dst.LoadKeypairs(ctx)
		require.NoError(t, err)
		require.Len(t, kps, 1, "a refused import writes nothing")

		_, err = dst.Import(ctx, src, ImportForce())
		require.NoError(t, err)
		kps, err = dst.LoadKeypairs(ctx)
		require.NoError(t, err)
		require.Len(t, kps, 2)
		for _, kp := range kps {
			require.NotEqual(t, "kid-target", kp.Kid, "force replaces what the target held")
		}

		_, err = dst.Import(ctx, src)
		require.ErrorIs(t, err, ErrTargetNotEmpty, "a second copy is refused too")
	})
}

// fakeSource reports fixed tables.
type fakeSource map[string]struct {
	columns []string
	rows    [][]any
}

func (f fakeSource) DumpTables(_ context.Context, visit func(string, []string, [][]any) error) error {
	for table, d := range f {
		if err := visit(table, d.columns, d.rows); err != nil {
			return err
		}
	}
	return nil
}

// sourceFrom returns a fakeSource with every table the real one has, edited
// by edit, so each case breaks exactly one thing.
func sourceFrom(t *testing.T, edit func(f fakeSource)) fakeSource {
	t.Helper()
	f := fakeSource{}
	for table, d := range dumpOf(t, newSQLiteSource(t)) {
		f[table] = struct {
			columns []string
			rows    [][]any
		}{d.columns, d.rows}
	}
	edit(f)
	return f
}

// A schema mismatch fails the whole copy, naming the table and column but
// never a value, and writes nothing.
func TestImportRefusesASchemaMismatch(t *testing.T) {
	forEachServer(t, func(t *testing.T, srv testServer) {
		cases := map[string]struct {
			edit func(f fakeSource)
			want string
		}{
			"extra source column": {
				edit: func(f fakeSource) {
					d := f["browser_sessions"]
					d.columns = append(d.columns, "new_col")
					for i := range d.rows {
						d.rows[i] = append(d.rows[i], "secret-in-new-col")
					}
					f["browser_sessions"] = d
				},
				want: "browser_sessions.new_col has no counterpart",
			},
			"missing source column": {
				edit: func(f fakeSource) {
					d := f["browser_sessions"]
					d.columns = d.columns[:len(d.columns)-1]
					for i := range d.rows {
						d.rows[i] = d.rows[i][:len(d.rows[i])-1]
					}
					f["browser_sessions"] = d
				},
				want: "is missing from the source",
			},
			"extra source table": {
				edit: func(f fakeSource) { f["new_table"] = f["jti_denylist"] },
				want: "source table new_table has no counterpart",
			},
			"missing source table": {
				edit: func(f fakeSource) { delete(f, "jti_denylist") },
				want: "table jti_denylist is missing from the source",
			},
			"derived table in the source": {
				edit: func(f fakeSource) { f["refresh_families"] = f["jti_denylist"] },
				want: "refresh_families is one this database derives",
			},
			"value of the wrong type": {
				edit: func(f fakeSource) {
					d := f["browser_sessions"]
					for i, c := range d.columns {
						if c == "created_at" {
							d.rows[0][i] = "sid-secret-not-a-time"
						}
					}
				},
				want: "browser_sessions.created_at: text value is not a timestamp",
			},
		}
		for name, tc := range cases {
			t.Run(name, func(t *testing.T) {
				dst := newTestStore(t, srv)
				_, err := dst.Import(t.Context(), sourceFrom(t, tc.edit))
				require.ErrorContains(t, err, tc.want)
				require.NotContains(t, err.Error(), "secret")
				var n int
				require.NoError(t, dst.pool.QueryRow(t.Context(), `SELECT count(*) FROM keypairs`).Scan(&n))
				require.Zero(t, n, "a failed import writes nothing")
			})
		}
	})
}

func TestImportValueConvertsSQLiteForms(t *testing.T) {
	cases := []struct {
		in       any
		dataType string
		want     any
	}{
		{"1970-01-01 00:00:00", "timestamp with time zone", time.Unix(0, 0).UTC()},
		{"2001-02-03 04:05:06.123456789 +0000 UTC", "timestamp with time zone", importT0},
		{"2001-02-03 06:05:06.123456+02:00", "timestamp with time zone", importT0},
		{importT0.Add(789).In(time.FixedZone("x", 3600)), "timestamp with time zone", importT0},
		{[]byte("pem"), "bytea", []byte("pem")},
		{"pem", "bytea", []byte("pem")},
		{[]byte("txt"), "text", "txt"},
		{int64(5), "integer", int64(5)},
		{nil, "text", nil},
	}
	for _, tc := range cases {
		got, err := importValue(tc.in, tc.dataType)
		require.NoError(t, err)
		if w, ok := tc.want.(time.Time); ok {
			require.True(t, w.Equal(got.(time.Time)), "%v: got %v", tc.in, got)
			require.Equal(t, time.UTC, got.(time.Time).Location())
			continue
		}
		require.Equal(t, tc.want, got)
	}

	_, err := importValue(int64(1), "numeric")
	require.ErrorContains(t, err, `no conversion for column type "numeric"`)
	_, err = importValue(1.5, "integer")
	require.ErrorContains(t, err, "cannot store a float64 in a column of type integer")
}

// A copy that fails part-way rolls back entirely: the target keeps exactly
// what it held, here one keypair of its own, and the error says what broke.
func TestImportFailuresRollBack(t *testing.T) {
	forEachServer(t, func(t *testing.T, srv testServer) {
		cases := map[string]struct {
			// force, if set, imports with ImportForce over the target's own
			// keypair.
			force bool
			setup func(t *testing.T, s *Store)
			src   func(t *testing.T) Source
			want  string
		}{
			"a table held by a running replica": {
				setup: func(t *testing.T, s *Store) {
					tx, err := s.pool.Begin(t.Context())
					require.NoError(t, err)
					t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
					_, err = tx.Exec(t.Context(), `LOCK TABLE keypairs IN ACCESS SHARE MODE`)
					require.NoError(t, err)
				},
				want: "lock tables (stop every replica first)",
			},
			"a row that cannot be cleared": {
				force: true,
				setup: func(t *testing.T, s *Store) { failOn(t, s, "keypairs", "DELETE") },
				want:  "clear keypairs",
			},
			"a row that cannot be written": {
				setup: func(t *testing.T, s *Store) { failOn(t, s, "jti_denylist", "INSERT") },
				want:  "copy jti_denylist",
			},
			"a derived table that cannot be rebuilt": {
				setup: func(t *testing.T, s *Store) { failOn(t, s, "refresh_families", "INSERT") },
				want:  "rebuild refresh_families",
			},
			"a row with too many values": {
				src: func(t *testing.T) Source {
					return sourceFrom(t, func(f fakeSource) {
						d := f["jti_denylist"]
						d.rows[0] = append(d.rows[0], "secret-extra-value")
					})
				},
				want: "a jti_denylist row has",
			},
		}
		for name, tc := range cases {
			t.Run(name, func(t *testing.T) {
				dst := newTestStore(t, srv)
				var opts []ImportOption
				if tc.force {
					opts = append(opts, ImportForce())
					require.NoError(t, dst.SaveKeypair(t.Context(), keys.Keypair{
						Kid: "kid-target", Alg: "RS256", PrivatePEM: []byte("p"), PublicPEM: []byte("p"), CreatedAt: importT0,
					}))
				}
				if tc.setup != nil {
					tc.setup(t, dst)
				}
				var src Source = newSQLiteSource(t)
				if tc.src != nil {
					src = tc.src(t)
				}

				_, err := dst.Import(t.Context(), src, opts...)
				require.ErrorContains(t, err, tc.want)
				require.NotContains(t, err.Error(), "secret")

				rows, err := dst.pool.Query(t.Context(), `SELECT kid FROM keypairs`)
				require.NoError(t, err)
				kids, err := pgx.CollectRows(rows, pgx.RowTo[string])
				require.NoError(t, err)
				if tc.force {
					require.Equal(t, []string{"kid-target"}, kids, "the target keeps what it held")
				} else {
					require.Empty(t, kids, "a failed import writes nothing")
				}
			})
		}
	})
}

// An unmigrated database has nothing to copy into.
func TestImportRefusesAnUnmigratedTarget(t *testing.T) {
	forEachServer(t, func(t *testing.T, srv testServer) {
		dst := newUnmigratedStore(t, srv)
		_, err := dst.Import(t.Context(), newSQLiteSource(t))
		require.ErrorContains(t, err, "the database has no tables; migrate it first")
	})
}
