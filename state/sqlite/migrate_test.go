package sqlite

import (
	"time"
)

// TestMigration0010AddsSubjectToExistingRows upgrades a database that has
// every other migration applied (a deployment of the release before 0010
// landed, which already ran 0011-0014) and holds live rows in every
// identity-carrying table. `migrate` fills in the missing lower version, and
// the rows survive with an empty subject: the oidc handlers treat that as a
// pre-upgrade grant and force a fresh sign-in rather than minting a token
// whose sub would be the email.
func (s *StoreSuite) TestMigration0010AddsSubjectToExistingRows() {
	legacy, err := New(WithPath(s.T().TempDir()+"/legacy.db"), WithBusyTimeout(time.Second))
	s.Require().NoError(err)
	defer func() { _ = legacy.Close() }()

	_, err = legacy.db.ExecContext(s.ctx, schemaVersionDDL)
	s.Require().NoError(err)
	migs, err := loadMigrations()
	s.Require().NoError(err)
	for _, m := range migs {
		if m.version == 10 {
			continue
		}
		s.Require().NoError(applyMigration(s.ctx, legacy.db, m))
	}
	s.Require().ErrorContains(legacy.IsCurrent(s.ctx), "schema is missing migrations 10")

	now := time.Now().UTC().Truncate(time.Microsecond)
	exp := now.Add(time.Hour)
	for _, stmt := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO auth_codes (code_hash, client_id, redirect_uri, email, scope, code_challenge, code_challenge_method, nonce, created_at, expires_at)
		  VALUES (?, 'ui', 'https://app/cb', 'alice@example.com', 'openid', '', '', '', ?, ?)`, []any{sha256Hex("c1"), now, exp}},
		{`INSERT INTO refresh_tokens (token_hash, jti, client_id, email, family_id, auth_time, created_at, expires_at)
		  VALUES (?, 'j1', 'ui', 'alice@example.com', 'f1', ?, ?, ?)`, []any{sha256Hex("r1"), now, now, exp}},
		{`INSERT INTO browser_sessions (sid_hash, email, created_at, expires_at)
		  VALUES (?, 'alice@example.com', ?, ?)`, []any{sha256Hex("s1"), now, exp}},
		{`INSERT INTO device_codes (device_code_hash, user_code, client_id, scope, email, approved_at, created_at, expires_at)
		  VALUES (?, 'USERCODE', 'tempogate-device', 'openid', 'alice@example.com', ?, ?, ?)`, []any{sha256Hex("d1"), now, now, exp}},
	} {
		_, err := legacy.db.ExecContext(s.ctx, stmt.sql, stmt.args...)
		s.Require().NoError(err)
	}

	s.Require().NoError(legacy.Migrate(s.ctx))
	s.Require().NoError(legacy.IsCurrent(s.ctx))

	ac, err := legacy.ConsumeAuthCode(s.ctx, "c1", "family-1", now)
	s.Require().NoError(err)
	s.Equal("alice@example.com", ac.Email)
	s.Empty(ac.Subject)

	rt, err := legacy.ConsumeRefresh(s.ctx, "r1", "ui", now)
	s.Require().NoError(err)
	s.Equal("alice@example.com", rt.Email)
	s.Empty(rt.Subject)

	bs, err := legacy.LookupBrowserSession(s.ctx, "s1")
	s.Require().NoError(err)
	s.Equal("alice@example.com", bs.Email)
	s.Empty(bs.Subject)

	dc, err := legacy.ConsumeDeviceCode(s.ctx, "d1")
	s.Require().NoError(err)
	s.Equal("alice@example.com", dc.Email)
	s.Empty(dc.Subject)
}
