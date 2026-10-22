package postgres

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/fx"

	"github.com/onhotpath/tempogate/admin"
	"github.com/onhotpath/tempogate/keys"
	"github.com/onhotpath/tempogate/oidc"
)

// failOn makes every op on table raise, so a statement part-way through a
// store transaction fails after the earlier ones succeeded.
func failOn(t *testing.T, s *Store, table, op string) {
	t.Helper()
	_, err := s.pool.Exec(t.Context(), fmt.Sprintf(`
		CREATE OR REPLACE FUNCTION injected_failure() RETURNS trigger LANGUAGE plpgsql AS
		$$ BEGIN RAISE EXCEPTION 'injected failure'; END $$;
		CREATE TRIGGER fail_%[1]s_%[2]s BEFORE %[2]s ON %[1]s FOR EACH ROW EXECUTE FUNCTION injected_failure();`,
		table, op))
	require.NoError(t, err)
}

// TestAFailedStatementRollsBackAndIsObserved: whichever statement of a
// store transaction fails, the call reports the database error (counted
// under its op) and leaves nothing half written.
func TestAFailedStatementRollsBackAndIsObserved(t *testing.T) {
	forEachServer(t, func(t *testing.T, srv testServer) {
		at := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
		kp := func(kid string) keys.Keypair {
			return keys.Keypair{Kid: kid, Alg: "RS256", PrivatePEM: []byte("p"), PublicPEM: []byte("p"), CreatedAt: at}
		}
		rt := func(token, family string) oidc.Refresh {
			return oidc.Refresh{Token: token, ClientID: "ui", Email: "a@example.com", Subject: "sub", FamilyID: family, AuthTime: at, CreatedAt: at, ExpiresAt: at.Add(time.Hour)}
		}
		cases := []struct {
			name, op, table, event string
			seed                   func(t *testing.T, s *Store)
			call                   func(t *testing.T, s *Store) error
			intact                 func(t *testing.T, s *Store)
		}{
			{
				name: "new refresh family", op: "save_refresh", table: "refresh_families", event: "INSERT",
				call: func(t *testing.T, s *Store) error { return s.SaveRefresh(t.Context(), rt("r", "fam")) },
				intact: func(t *testing.T, s *Store) {
					require.Zero(t, count(t, s, "refresh_tokens"))
				},
			},
			{
				name: "refresh token insert", op: "save_refresh", table: "refresh_tokens", event: "INSERT",
				call: func(t *testing.T, s *Store) error { return s.SaveRefresh(t.Context(), rt("r", "fam")) },
				intact: func(t *testing.T, s *Store) {
					require.Zero(t, count(t, s, "refresh_families"), "the family row goes with the failed token")
				},
			},
			{
				name: "revoke family tokens", op: "revoke_refresh", table: "refresh_tokens", event: "UPDATE",
				seed: func(t *testing.T, s *Store) { require.NoError(t, s.SaveRefresh(t.Context(), rt("r", "fam"))) },
				call: func(t *testing.T, s *Store) error {
					_, err := s.RevokeRefreshFamily(t.Context(), "fam", at)
					return err
				},
				intact: func(t *testing.T, s *Store) {
					var revoked int
					require.NoError(t, s.pool.QueryRow(t.Context(), `SELECT count(revoked_at) FROM refresh_families`).Scan(&revoked))
					require.Zero(t, revoked, "the family is not marked revoked either")
				},
			},
			{
				name: "revoke by email", op: "revoke_refresh", table: "refresh_tokens", event: "UPDATE",
				seed: func(t *testing.T, s *Store) { require.NoError(t, s.SaveRefresh(t.Context(), rt("r", "fam"))) },
				call: func(t *testing.T, s *Store) error {
					_, err := s.RevokeRefreshByEmail(t.Context(), "a@example.com", at)
					return err
				},
			},
			{
				name: "revoke by subject", op: "revoke_refresh", table: "refresh_families", event: "UPDATE",
				seed: func(t *testing.T, s *Store) { require.NoError(t, s.SaveRefresh(t.Context(), rt("r", "fam"))) },
				call: func(t *testing.T, s *Store) error {
					_, err := s.RevokeRefreshBySubject(t.Context(), "sub", at)
					return err
				},
			},
			{
				name: "save keypair", op: "save_keypair", table: "keypairs", event: "INSERT",
				call: func(t *testing.T, s *Store) error { return s.SaveKeypair(t.Context(), kp("a")) },
			},
			{
				name: "retire keypair", op: "retire_keypair", table: "keypairs", event: "UPDATE",
				seed: func(t *testing.T, s *Store) {
					require.NoError(t, s.SaveKeypair(t.Context(), kp("a")))
					require.NoError(t, s.SaveKeypair(t.Context(), kp("b")))
				},
				call: func(t *testing.T, s *Store) error { _, err := s.RetireKeypair(t.Context(), "a", at); return err },
			},
			{
				name: "rewrite private key", op: "update_keypair_private_pem", table: "keypairs", event: "UPDATE",
				seed: func(t *testing.T, s *Store) { require.NoError(t, s.SaveKeypair(t.Context(), kp("a"))) },
				call: func(t *testing.T, s *Store) error {
					return s.UpdateKeypairPrivatePEM(t.Context(), "a", []byte("sealed"))
				},
			},
			{
				name: "denylist a revoked key", op: "mark_integration_key_revoked", table: "jti_denylist", event: "INSERT",
				seed: func(t *testing.T, s *Store) {
					require.NoError(t, s.SaveIntegrationKey(t.Context(), admin.IntegrationKey{ID: "k", Namespace: "ns", Role: admin.RoleRead, Owner: "o", JTI: "j", CreatedAt: at}))
				},
				call: func(t *testing.T, s *Store) error {
					_, err := s.MarkIntegrationKeyRevoked(t.Context(), "k", at)
					return err
				},
				intact: func(t *testing.T, s *Store) {
					k, err := s.IntegrationKeyByID(t.Context(), "k")
					require.NoError(t, err)
					require.Nil(t, k.RevokedAt, "the key row is not revoked without its denylist row")
				},
			},
			{
				name: "poll device code", op: "poll_device_code", table: "device_codes", event: "UPDATE",
				seed: func(t *testing.T, s *Store) {
					require.NoError(t, s.SaveDeviceCode(t.Context(), oidc.DeviceCode{Code: "dc", UserCode: "ABCDEFGH", IntervalSeconds: 5, CreatedAt: at, ExpiresAt: at.Add(time.Hour)}))
				},
				call: func(t *testing.T, s *Store) error { _, err := s.PollDeviceCode(t.Context(), "dc", at); return err },
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				obs := &recordingObserver{}
				s := newTestStore(t, srv, WithErrorObserver(obs))
				if tc.seed != nil {
					tc.seed(t, s)
				}
				failOn(t, s, tc.table, tc.event)
				err := tc.call(t, s)
				require.ErrorContains(t, err, "injected failure")
				require.Equal(t, []string{tc.op}, obs.calls())
				if tc.intact != nil {
					tc.intact(t, s)
				}
			})
		}

		t.Run("a notification too large to send", func(t *testing.T) {
			obs := &recordingObserver{}
			s := newTestStore(t, srv, WithErrorObserver(obs))
			jti := strings.Repeat("j", 9000) // NOTIFY payloads stop at 8000 bytes
			require.NoError(t, s.SaveIntegrationKey(t.Context(), admin.IntegrationKey{ID: "k", Namespace: "ns", Role: admin.RoleRead, Owner: "o", JTI: jti, CreatedAt: at}))
			_, err := s.MarkIntegrationKeyRevoked(t.Context(), "k", at)
			require.Error(t, err)
			require.Equal(t, []string{"mark_integration_key_revoked"}, obs.calls())
			revoked, err := s.IsRevoked(t.Context(), jti)
			require.NoError(t, err)
			require.False(t, revoked, "the revocation rolled back with its notification")
		})

		t.Run("migrate without the right to create tables", func(t *testing.T) {
			s := newUnmigratedStore(t, srv)
			role := "ro_" + strings.ToLower(strings.ReplaceAll(t.Name(), "/", "_"))[:20]
			_, err := s.pool.Exec(t.Context(), fmt.Sprintf(`
				DROP ROLE IF EXISTS %[1]s;
				CREATE ROLE %[1]s LOGIN PASSWORD 'pw';
				REVOKE CREATE ON SCHEMA public FROM PUBLIC;`, role))
			require.NoError(t, err)
			t.Cleanup(func() {
				_, _ = s.pool.Exec(context.WithoutCancel(t.Context()), `REASSIGN OWNED BY `+role+` TO CURRENT_USER; DROP OWNED BY `+role+`; DROP ROLE `+role)
			})
			cfg := s.pool.Config().ConnConfig
			restricted := newStoreOn(t, fmt.Sprintf("postgres://%s:pw@%s:%d/%s?sslmode=disable", role, cfg.Host, cfg.Port, cfg.Database))
			require.ErrorContains(t, restricted.Migrate(t.Context()), "postgres: create schema_migrations: ")
			require.ErrorContains(t, restricted.IsCurrent(t.Context()), "schema version 0", "reading needs no DDL right")
		})

		t.Run("a migration that records itself", func(t *testing.T) {
			s := newUnmigratedStore(t, srv, withMigrations(fstest.MapFS{
				"migrations/0001_self.sql": {Data: []byte(`INSERT INTO schema_migrations VALUES (1, 'self', '2030-01-01T00:00:00Z')`)},
			}))
			require.ErrorContains(t, s.Migrate(t.Context()), "postgres: record 1_self: ")
		})
	})

	t.Run("Fx", func(t *testing.T) {
		supply := func(interval time.Duration) fx.Option {
			return fx.Supply(
				fx.Annotated{Name: "postgres_dsn", Target: "postgres://tempogate@127.0.0.1:1/tempogate"},
				fx.Annotated{Name: "postgres_dsn_file", Target: ""},
				fx.Annotated{Name: "postgres_listen_dsn", Target: ""},
				fx.Annotated{Name: "postgres_max_conns", Target: 2},
				fx.Annotated{Name: "postgres_conn_max_idle_time", Target: time.Minute},
				fx.Annotated{Name: "postgres_allow_insecure_sslmode", Target: false},
				fx.Annotated{Name: "state_reaper_interval", Target: interval},
				fx.Annotated{Name: "oidc_refresh_max_lifetime", Target: time.Hour},
			)
		}
		app := fx.New(fx.NopLogger, supply(time.Minute), Fx(), fx.Invoke(func(*Store, *Reaper, keys.BootstrapLocker, admin.SessionStore, admin.KeyRegistry) {}))
		require.NoError(t, app.Err())
		require.NoError(t, app.Start(t.Context()))
		require.NoError(t, app.Stop(t.Context()))

		app = fx.New(fx.NopLogger, supply(-time.Minute), Fx(), fx.Invoke(func(*Reaper) {}))
		require.ErrorContains(t, app.Err(), "STATE_REAPER_INTERVAL must not be negative")

	})

	t.Run("PingUnreachable", func(t *testing.T) {
		s, err := New(WithDSN("postgres://tempogate@127.0.0.1:1/tempogate?connect_timeout=2"))
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, s.Close()) })
		require.ErrorContains(t, s.Ping(t.Context()), "postgres: ping: ")
		require.Error(t, s.Probe(t.Context()), "the default observer swallows the report")
	})
}
