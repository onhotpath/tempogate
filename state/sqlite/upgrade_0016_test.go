package sqlite

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"

	"github.com/onhotpath/tempogate/keys"
	"github.com/onhotpath/tempogate/oidc"
	"github.com/onhotpath/tempogate/oidc/connector/google"
	"github.com/onhotpath/tempogate/perms"
)

// TestMigration0016KeepsPreUpgradeSessionsWorking upgrades a database at
// schema 0015 holding rows exactly as the previous release wrote them (no
// connector_id) and proves they are Google's after `migrate`: a pending
// sign-in, an unredeemed code, a browser session and an approved device code
// read back as google, and a refresh token and the approved device code
// still mint tokens, now with sub google:<sub> and idp google.
func (s *StoreSuite) TestMigration0016KeepsPreUpgradeSessionsWorking() {
	legacy, err := New(WithPath(s.T().TempDir()+"/legacy.db"), WithBusyTimeout(time.Second))
	s.Require().NoError(err)
	defer func() { _ = legacy.Close() }()

	_, err = legacy.db.ExecContext(s.ctx, schemaVersionDDL)
	s.Require().NoError(err)
	migs, err := loadMigrations()
	s.Require().NoError(err)
	for _, m := range migs {
		if m.Version < 16 {
			s.Require().NoError(applyMigration(s.ctx, legacy.db, m))
		}
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	exp := now.Add(time.Hour)
	for _, stmt := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO auth_requests (internal_state, client_id, redirect_uri, scope, client_state, code_challenge, code_challenge_method, nonce, created_at, expires_at)
		  VALUES ('st-1', 'ui', 'https://app/cb', 'openid', '', '', '', '', ?, ?)`, []any{now, exp}},
		{`INSERT INTO auth_codes (code_hash, client_id, redirect_uri, subject, email, scope, code_challenge, code_challenge_method, nonce, created_at, expires_at)
		  VALUES (?, 'ui', 'https://app/cb', 'sub-alice', 'alice@example.com', 'openid', '', '', '', ?, ?)`, []any{sha256Hex("c1"), now, exp}},
		{`INSERT INTO refresh_tokens (token_hash, jti, client_id, subject, email, family_id, auth_time, created_at, expires_at)
		  VALUES (?, 'j1', 'ui', 'sub-alice', 'alice@example.com', 'fam-1', ?, ?, ?)`, []any{sha256Hex("r1"), now, now, exp}},
		{`INSERT INTO browser_sessions (sid_hash, subject, email, created_at, expires_at)
		  VALUES (?, 'sub-alice', 'alice@example.com', ?, ?)`, []any{sha256Hex("s1"), now, exp}},
		{`INSERT INTO device_codes (device_code_hash, user_code, client_id, scope, subject, email, approved_at, interval_seconds, created_at, expires_at)
		  VALUES (?, 'APPROVED', 'tempogate-device', 'openid', 'sub-alice', 'alice@example.com', ?, 5, ?, ?)`, []any{sha256Hex("d1"), now, now, exp}},
		{`INSERT INTO device_codes (device_code_hash, user_code, client_id, scope, interval_seconds, created_at, expires_at)
		  VALUES (?, 'PENDINGX', 'tempogate-device', 'openid', 5, ?, ?)`, []any{sha256Hex("d2"), now, exp}},
	} {
		_, err := legacy.db.ExecContext(s.ctx, stmt.sql, stmt.args...)
		s.Require().NoError(err)
	}

	s.Require().NoError(legacy.Migrate(s.ctx))
	s.Require().NoError(legacy.IsCurrent(s.ctx))

	ar, err := legacy.ConsumeAuthRequest(s.ctx, "st-1")
	s.Require().NoError(err)
	s.Equal("google", ar.ConnectorID, "a sign-in started before the upgrade completes at /callback/google")
	ac, err := legacy.ConsumeAuthCode(s.ctx, "c1", "fam-c", now)
	s.Require().NoError(err)
	s.Equal("google", ac.ConnectorID)
	bs, err := legacy.LookupBrowserSession(s.ctx, "s1")
	s.Require().NoError(err)
	s.Equal("google", bs.ConnectorID)
	pending, err := legacy.LookupDeviceCodeByUserCode(s.ctx, "PENDINGX")
	s.Require().NoError(err)
	s.Empty(pending.ConnectorID, "a pending device code gets its connector on approval")

	srv := s.tokenServer(legacy)
	refreshed := s.postToken(srv, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"r1"}, "client_id": {"ui"}})
	device := s.postToken(srv, url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {"d1"}, "client_id": {"tempogate-device"}})
	for name, claims := range map[string]map[string]any{"refresh": refreshed, "device": device} {
		s.Equal("google:sub-alice", claims["sub"], name)
		s.Equal("google", claims["idp"], name)
	}
}

// tokenServer serves /token over store the way serve wires it, with the
// Google connector configured.
func (s *StoreSuite) tokenServer(store *Store) *httptest.Server {
	k := keys.New(keys.WithStore(store), keys.WithGenerateOptions(keys.WithRSABits(2048)))
	s.Require().NoError(k.Init(s.ctx))
	conn, err := google.NewConnector(google.Config{AuthEndpoint: "https://accounts.google.com/o/oauth2/v2/auth"}, nil)
	s.Require().NoError(err)
	conns, err := oidc.NewConnectors(conn)
	s.Require().NoError(err)
	reg, err := oidc.ParseClientRegistry("ui:https://app/cb,tempogate-device:")
	s.Require().NoError(err)
	tok := oidc.NewToken(store, keys.NewSigner(keys.WithKeys(k)), reg,
		oidc.WithDeviceCodeStore(store),
		oidc.WithConnectors(conns),
		oidc.WithAllowedDomains("example.com"),
		oidc.WithPermissionResolver(permitEveryone{}),
	)
	mux := http.NewServeMux()
	tok.Register(humago.New(mux, huma.DefaultConfig("test", "0.0.0")))
	srv := httptest.NewServer(mux)
	s.T().Cleanup(srv.Close)
	return srv
}

// postToken redeems form and returns the access token's claims, unverified:
// the signature is the keys package's concern, the claims are this test's.
func (s *StoreSuite) postToken(srv *httptest.Server, form url.Values) map[string]any {
	resp, err := http.PostForm(srv.URL+"/token", form)
	s.Require().NoError(err)
	defer func() { _ = resp.Body.Close() }()
	var body struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error_description"`
	}
	s.Require().NoError(json.NewDecoder(resp.Body).Decode(&body))
	s.Require().Equal(http.StatusOK, resp.StatusCode, body.Error)
	parts := strings.Split(body.AccessToken, ".")
	s.Require().Len(parts, 3)
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	s.Require().NoError(err)
	var claims map[string]any
	s.Require().NoError(json.Unmarshal(raw, &claims))
	return claims
}

// permitEveryone grants every admitted person cluster admin; authorization
// is not what this test is about.
type permitEveryone struct{}

func (permitEveryone) Resolve(context.Context, string) (*perms.Grant, error) {
	return perms.ParseClaim([]string{"temporal-system:admin"})
}
