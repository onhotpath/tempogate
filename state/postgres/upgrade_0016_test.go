package postgres

import (
	"fmt"
	"io/fs"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/onhotpath/tempogate/internal/clock"
	"github.com/onhotpath/tempogate/state/internal/migration"
	"github.com/onhotpath/tempogate/state/internal/secret"
)

// TestMigration0016KeepsPreUpgradeSessionsWorking upgrades a database at
// schema 0015 holding rows exactly as the previous release wrote them (no
// connector_id) and proves they are Google's after `migrate`, as
// state/sqlite's twin does: a pending sign-in, an unredeemed code, a browser
// session, a refresh token and an approved device code read back as google,
// and a pending device code gets its connector only on approval. The
// columns keep no default, so a writer that forgets one fails loudly.
func TestMigration0016KeepsPreUpgradeSessionsWorking(t *testing.T) {
	forEachServer(t, func(t *testing.T, srv testServer) {
		dsn := newDatabase(t, srv)
		legacy := newStoreOn(t, dsn, withMigrations(migrationsBelow(t, 16)))
		require.NoError(t, legacy.Migrate(t.Context()))

		now := clock.Now()
		exp := now.Add(time.Hour)
		for _, stmt := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO auth_requests (internal_state, client_id, redirect_uri, scope, client_state, code_challenge, code_challenge_method, nonce, created_at, expires_at)
			  VALUES ('st-1', 'ui', 'https://app/cb', 'openid', '', '', '', '', $1, $2)`, []any{now, exp}},
			{`INSERT INTO auth_codes (code_hash, client_id, redirect_uri, subject, email, scope, code_challenge, code_challenge_method, nonce, created_at, expires_at)
			  VALUES ($1, 'ui', 'https://app/cb', 'sub-alice', 'alice@example.com', 'openid', '', '', '', $2, $3)`, []any{secret.Hash("c1"), now, exp}},
			{`INSERT INTO refresh_tokens (token_hash, jti, client_id, subject, email, family_id, auth_time, created_at, expires_at)
			  VALUES ($1, 'j1', 'ui', 'sub-alice', 'alice@example.com', 'fam-1', $2, $2, $3)`, []any{secret.Hash("r1"), now, exp}},
			{`INSERT INTO refresh_families (family_id) VALUES ('fam-1')`, nil},
			{`INSERT INTO browser_sessions (sid_hash, subject, email, created_at, expires_at)
			  VALUES ($1, 'sub-alice', 'alice@example.com', $2, $3)`, []any{secret.Hash("s1"), now, exp}},
			{`INSERT INTO device_codes (device_code_hash, user_code, client_id, scope, subject, email, approved_at, interval_seconds, created_at, expires_at)
			  VALUES ($1, 'APPROVED', 'tempogate-device', 'openid', 'sub-alice', 'alice@example.com', $2, 5, $2, $3)`, []any{secret.Hash("d1"), now, exp}},
			{`INSERT INTO device_codes (device_code_hash, user_code, client_id, scope, interval_seconds, created_at, expires_at)
			  VALUES ($1, 'PENDINGX', 'tempogate-device', 'openid', 5, $2, $3)`, []any{secret.Hash("d2"), now, exp}},
		} {
			_, err := legacy.pool.Exec(t.Context(), stmt.sql, stmt.args...)
			require.NoError(t, err)
		}

		s := newStoreOn(t, dsn)
		require.NoError(t, s.Migrate(t.Context()))
		require.NoError(t, s.IsCurrent(t.Context()))

		ctx := t.Context()
		ar, err := s.ConsumeAuthRequest(ctx, "st-1")
		require.NoError(t, err)
		require.Equal(t, "google", ar.ConnectorID, "a sign-in started before the upgrade completes at /callback/google")
		ac, err := s.ConsumeAuthCode(ctx, "c1", "fam-c", now)
		require.NoError(t, err)
		require.Equal(t, "google", ac.ConnectorID)
		bs, err := s.LookupBrowserSession(ctx, "s1")
		require.NoError(t, err)
		require.Equal(t, "google", bs.ConnectorID)
		rt, err := s.ConsumeRefresh(ctx, "r1", "ui", now)
		require.NoError(t, err)
		require.Equal(t, "google", rt.ConnectorID)
		approved, err := s.ConsumeDeviceCode(ctx, "d1")
		require.NoError(t, err)
		require.Equal(t, "google", approved.ConnectorID)
		require.Equal(t, "sub-alice", approved.Subject)
		pending, err := s.LookupDeviceCodeByUserCode(ctx, "PENDINGX")
		require.NoError(t, err)
		require.Empty(t, pending.ConnectorID, "a pending device code gets its connector on approval")

		rows, err := s.pool.Query(ctx,
			`SELECT table_name || ' ' || is_nullable || ' ' || coalesce(column_default, '<none>')
			 FROM information_schema.columns
			 WHERE table_schema = current_schema() AND column_name = 'connector_id'
			 ORDER BY table_name`)
		require.NoError(t, err)
		cols, err := pgx.CollectRows(rows, pgx.RowTo[string])
		require.NoError(t, err)
		require.Equal(t, []string{
			"auth_codes NO <none>",
			"auth_requests NO <none>",
			"browser_sessions NO <none>",
			"device_codes YES <none>",
			"refresh_tokens NO <none>",
		}, cols)
	})
}

// migrationsBelow is the embedded migrations older than version, the schema
// a previous release left behind.
func migrationsBelow(t *testing.T, version int) fs.FS {
	t.Helper()
	migs, err := migration.Load(migrationsFS, "migrations", "postgres")
	require.NoError(t, err)
	out := fstest.MapFS{}
	for _, m := range migs {
		if m.Version < version {
			out[fmt.Sprintf("migrations/%04d_%s.sql", m.Version, m.Name)] = &fstest.MapFile{Data: []byte(m.SQL)}
		}
	}
	return out
}
