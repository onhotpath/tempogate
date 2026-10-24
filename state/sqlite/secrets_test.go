package sqlite

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/onhotpath/tempogate/keys"
	"github.com/onhotpath/tempogate/oidc"
)

func sha256Hex(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}

func browserSessionAt(sid string, now time.Time) oidc.BrowserSession {
	return oidc.BrowserSession{SID: sid, Email: "alice@example.com", CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
}

// seedEverySecret writes one of each bearer secret the store holds, live and
// consumed, and returns the raw values by name.
func seedEverySecret(t *testing.T, s *Store) map[string]string {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, s.Migrate(ctx))
	now := time.Now().UTC()
	secrets := map[string]string{
		"live refresh token":     "rt-live-Zq3xV9sJ2mN8bP4kL7wT1cY6",
		"consumed refresh token": "rt-used-Hd5gF2aQ9rE3uI8oP1sD7fG4",
		"live auth code":         "ac-live-Wm2nB5vC8xZ1qA4sD7fG0hJ3",
		"consumed auth code":     "ac-used-Kp9oI6uY3tR0eW7qA4sD1fG8",
		"live device code":       "dc-live-Lk8jH5gF2dS9aQ6wE3rT0yU7",
		"consumed device code":   "dc-used-Mn4bV1cX8zL5kJ2hG9fD6sA3",
		"browser session id":     "sid-live-Po7iU4yT1rE8wQ5aS2dF9gH6",
	}
	for _, key := range []string{"live refresh token", "consumed refresh token"} {
		r := oidc.Refresh{
			Token: secrets[key], JTI: "jti-" + key, ClientID: "tempogate-cli", Email: "alice@example.com",
			FamilyID: "family-1", AuthTime: now, CreatedAt: now, ExpiresAt: now.Add(time.Hour),
		}
		require.NoError(t, s.SaveRefresh(ctx, r))
	}
	_, err := s.ConsumeRefresh(ctx, secrets["consumed refresh token"], "tempogate-cli", now)
	require.NoError(t, err)

	for _, key := range []string{"live auth code", "consumed auth code"} {
		require.NoError(t, s.SaveAuthCode(ctx, oidc.AuthCode{
			Code: secrets[key], ClientID: "tempogate-cli", RedirectURI: "http://127.0.0.1/callback",
			Email: "alice@example.com", Scope: "openid", CodeChallenge: "c", CodeChallengeMethod: "S256",
			CreatedAt: now, ExpiresAt: now.Add(time.Minute),
		}))
	}
	_, err = s.ConsumeAuthCode(ctx, secrets["consumed auth code"], "fam", now)
	require.NoError(t, err)

	for i, key := range []string{"live device code", "consumed device code"} {
		require.NoError(t, s.SaveDeviceCode(ctx, oidc.DeviceCode{
			Code: secrets[key], UserCode: []string{"BCDFGHJK", "LMNPQRST"}[i], ClientID: "tempogate-device",
			Scope: "openid", IntervalSeconds: 5, CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute),
		}))
	}
	_, err = s.ConsumeDeviceCode(ctx, secrets["consumed device code"])
	require.NoError(t, err)

	require.NoError(t, s.SaveBrowserSession(ctx, browserSessionAt(secrets["browser session id"], now)))
	return secrets
}

// Every bearer secret is stored as its SHA-256, and the store finds rows by
// that hash: a row written directly with only the hash is found by the raw
// value.
func (s *StoreSuite) TestSecretsAreStoredAsSHA256() {
	secrets := seedEverySecret(s.T(), s.store)

	var got string
	s.Require().NoError(s.store.db.QueryRowContext(s.ctx,
		`SELECT token_hash FROM refresh_tokens WHERE consumed_at IS NULL`).Scan(&got))
	s.Equal(sha256Hex(secrets["live refresh token"]), got)
	s.Require().NoError(s.store.db.QueryRowContext(s.ctx, `SELECT code_hash FROM auth_codes WHERE consumed_at IS NULL`).Scan(&got))
	s.Equal(sha256Hex(secrets["live auth code"]), got)
	s.Require().NoError(s.store.db.QueryRowContext(s.ctx, `SELECT device_code_hash FROM device_codes`).Scan(&got))
	s.Equal(sha256Hex(secrets["live device code"]), got)
	s.Require().NoError(s.store.db.QueryRowContext(s.ctx, `SELECT sid_hash FROM browser_sessions`).Scan(&got))
	s.Equal(sha256Hex(secrets["browser session id"]), got)
}

func (s *StoreSuite) TestLookupsMatchRowsByHash() {
	now := time.Now().UTC()
	_, err := s.store.db.ExecContext(s.ctx,
		`INSERT INTO browser_sessions (sid_hash, email, created_at, expires_at) VALUES (?, 'bob@example.com', ?, ?)`,
		sha256Hex("sid-by-hash"), now, now.Add(time.Minute))
	s.Require().NoError(err)
	bs, err := s.store.LookupBrowserSession(s.ctx, "sid-by-hash")
	s.Require().NoError(err)
	s.Equal("sid-by-hash", bs.SID, "the caller's raw value is echoed back; the store never holds it")
	s.Equal("bob@example.com", bs.Email)

	_, err = s.store.LookupBrowserSession(s.ctx, sha256Hex("sid-by-hash"))
	s.Require().ErrorIs(err, oidc.ErrBrowserSessionNotFound, "presenting the stored hash itself is not a credential")

	_, err = s.store.db.ExecContext(s.ctx,
		`INSERT INTO auth_codes (code_hash, client_id, redirect_uri, email, scope, code_challenge,
		   code_challenge_method, created_at, expires_at)
		 VALUES (?, 'ui', 'https://x/cb', 'bob@example.com', 'openid', 'c', 'S256', ?, ?)`,
		sha256Hex("code-by-hash"), now, now.Add(time.Minute))
	s.Require().NoError(err)
	ac, err := s.store.ConsumeAuthCode(s.ctx, "code-by-hash", "fam", time.Now())
	s.Require().NoError(err)
	s.Equal("code-by-hash", ac.Code)
}

// Lookups by user_code (stored in clear: see migration 0012) cannot return
// the device code, which only exists as a hash.
func (s *StoreSuite) TestLookupByUserCodeOmitsDeviceCode() {
	s.Require().NoError(s.store.SaveDeviceCode(s.ctx, s.deviceCode("dc-secret", "BCDFGHJK")))
	got, err := s.store.LookupDeviceCodeByUserCode(s.ctx, "BCDFGHJK")
	s.Require().NoError(err)
	s.Empty(got.Code)
	s.Equal("BCDFGHJK", got.UserCode)
}

// migrateTo applies the embedded migrations up to and including version,
// so a test can seed rows in the shape an older release left them.
func migrateTo(t *testing.T, s *Store, version int) {
	t.Helper()
	ctx := context.Background()
	_, err := s.db.ExecContext(ctx, schemaVersionDDL)
	require.NoError(t, err)
	migs, err := loadMigrations()
	require.NoError(t, err)
	applied, err := loadAppliedVersions(ctx, s.db)
	require.NoError(t, err)
	for _, m := range migs {
		if _, done := applied[m.Version]; !done && m.Version <= version {
			require.NoError(t, applyMigration(ctx, s.db, m))
		}
	}
}

// seedPre0012 writes rows in the 0011 shape, where every secret column
// holds the raw value.
func seedPre0012(t *testing.T, s *Store) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	exp := now.Add(time.Hour)
	for _, stmt := range []string{
		`INSERT INTO refresh_tokens (token, jti, client_id, email, created_at, expires_at, auth_time, family_id)
		 VALUES ('raw-refresh', 'jti-1', 'tempogate-cli', 'alice@example.com', ?1, ?2, ?1, 'fam')`,
		`INSERT INTO auth_codes (code, client_id, redirect_uri, email, scope, code_challenge,
		   code_challenge_method, created_at, expires_at)
		 VALUES ('raw-code', 'ui', 'https://x/cb', 'alice@example.com', 'openid', 'c', 'S256', ?1, ?2)`,
		`INSERT INTO device_codes (device_code, user_code, client_id, scope, created_at, expires_at)
		 VALUES ('raw-device', 'BCDFGHJK', 'tempogate-device', 'openid', ?1, ?2)`,
		`INSERT INTO browser_sessions (sid, email, created_at, expires_at)
		 VALUES ('raw-sid', 'alice@example.com', ?1, ?2)`,
	} {
		_, err := s.db.ExecContext(ctx, stmt, now, exp)
		require.NoError(t, err, stmt)
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO keypairs (kid, alg, private_pem, public_pem, created_at) VALUES ('kid-1', 'RS256', 'priv', 'pub', ?)`, now)
	require.NoError(t, err)
}

// Migration 0012 cannot hash the existing raw values in SQL (SQLite has no
// SHA-256), so it drops the short-lived rows: one re-login. Everything else
// survives.
func TestMigration0012DropsRawSecrets(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "legacy.db")
	s, err := New(WithPath(path))
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	migrateTo(t, s, 11)
	seedPre0012(t, s)

	require.NoError(t, s.Migrate(ctx))
	require.NoError(t, s.IsCurrent(ctx))

	for _, table := range []string{"refresh_tokens", "auth_codes", "device_codes", "browser_sessions"} {
		var n int
		require.NoError(t, s.db.QueryRowContext(ctx, `SELECT count(*) FROM `+table).Scan(&n))
		require.Zerof(t, n, "%s rows held raw secrets and are dropped", table)
	}
	var kid string
	require.NoError(t, s.db.QueryRowContext(ctx, `SELECT kid FROM keypairs`).Scan(&kid))
	require.Equal(t, "kid-1", kid, "signing keys survive")

	_, err = s.ConsumeRefresh(ctx, "raw-refresh", "tempogate-cli", time.Now().UTC())
	require.ErrorIs(t, err, oidc.ErrRefreshNotFound)
}

// 0012 renames the secret columns in place rather than rebuilding the
// tables, so columns another migration added (a parallel 0010 adds
// `subject` to all four) survive it.
func TestMigration0012PreservesOtherColumns(t *testing.T) {
	ctx := context.Background()
	s, err := New(WithPath(filepath.Join(t.TempDir(), "parallel.db")))
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	migrateTo(t, s, 11)
	for _, table := range []string{"refresh_tokens", "auth_codes", "device_codes", "browser_sessions"} {
		_, err := s.db.ExecContext(ctx, `ALTER TABLE `+table+` ADD COLUMN extra_col TEXT NOT NULL DEFAULT ''`)
		require.NoError(t, err)
	}

	require.NoError(t, s.Migrate(ctx))

	for _, table := range []string{"refresh_tokens", "auth_codes", "device_codes", "browser_sessions"} {
		_, err := s.db.ExecContext(ctx, `SELECT extra_col FROM `+table)
		require.NoErrorf(t, err, "%s kept the column added by another migration", table)
	}
}

func (s *StoreSuite) TestUpdateKeypairPrivatePEM() {
	kp := keys.Keypair{Kid: "kid-u", Alg: "RS256", PrivatePEM: []byte("plain"), PublicPEM: []byte("pub"), CreatedAt: time.Now().UTC()}
	s.Require().NoError(s.store.SaveKeypair(s.ctx, kp))
	s.Require().NoError(s.store.UpdateKeypairPrivatePEM(s.ctx, "kid-u", []byte("sealed")))

	got, err := s.store.LoadKeypairs(s.ctx)
	s.Require().NoError(err)
	s.Require().Len(got, 1)
	s.Equal([]byte("sealed"), got[0].PrivatePEM)
	s.Equal([]byte("pub"), got[0].PublicPEM)

	s.Require().ErrorContains(s.store.UpdateKeypairPrivatePEM(s.ctx, "kid-missing", []byte("x")), "kid-missing")
}

func (s *StoreSuite) TestUpdateKeypairPrivatePEMAfterClose() {
	s.Require().NoError(s.store.Close())
	s.Require().Error(s.store.UpdateKeypairPrivatePEM(s.ctx, "kid", []byte("x")))
	s.store = nil
}
