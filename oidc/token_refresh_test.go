package oidc_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	jwxjwt "github.com/lestrrat-go/jwx/v4/jwt"

	"github.com/onhotpath/tempogate/oidc"
)

// TestRefreshGrantBindsAndAuthenticatesClient is the M2 regression: a
// refresh token is redeemable only by the client it was issued to (RFC 9700
// §4.14), which must authenticate when it is confidential (RFC 6749 §6).
// Every rejection is decided before the token is consumed, so a failed or
// cross-client attempt cannot burn the legitimate client's session.
func (s *TokenSuite) TestRefreshGrantBindsAndAuthenticatesClient() {
	const (
		publicRT = "rt-public" // issued to the public client "ui"
		confRT   = "rt-conf"   // issued to the confidential client "webui"
	)
	cases := []struct {
		name       string
		token      string
		clientID   string // client_id in the body
		formSecret string // client_secret in the body
		basic      bool   // send clientID:basicSecret as HTTP Basic instead
		basicPass  string
		wantStatus int
		wantErr    string
		wantAud    string
	}{
		{name: "public client, matching client_id", token: publicRT, clientID: "ui", wantStatus: http.StatusOK, wantAud: "ui"},
		{name: "public client, missing client_id", token: publicRT, wantStatus: http.StatusUnauthorized, wantErr: "invalid_client"},
		{name: "public client, unknown client_id", token: publicRT, clientID: "someone-else", wantStatus: http.StatusUnauthorized, wantErr: "invalid_client"},
		{name: "public token presented by authenticated confidential client", token: publicRT, clientID: "webui", formSecret: confidentialSecret, wantStatus: http.StatusBadRequest, wantErr: "invalid_grant"},
		{name: "confidential token presented by public client", token: confRT, clientID: "ui", wantStatus: http.StatusBadRequest, wantErr: "invalid_grant"},
		{name: "confidential client, no secret", token: confRT, clientID: "webui", wantStatus: http.StatusUnauthorized, wantErr: "invalid_client"},
		{name: "confidential client, missing client_id", token: confRT, wantStatus: http.StatusUnauthorized, wantErr: "invalid_client"},
		{name: "confidential client, wrong form secret", token: confRT, clientID: "webui", formSecret: "not-the-secret", wantStatus: http.StatusUnauthorized, wantErr: "invalid_client"},
		{name: "confidential client, wrong basic secret", token: confRT, clientID: "webui", basic: true, basicPass: "not-the-secret", wantStatus: http.StatusUnauthorized, wantErr: "invalid_client"},
		{name: "confidential client, form secret", token: confRT, clientID: "webui", formSecret: confidentialSecret, wantStatus: http.StatusOK, wantAud: "webui"},
		{name: "confidential client, basic secret", token: confRT, clientID: "webui", basic: true, basicPass: confidentialSecret, wantStatus: http.StatusOK, wantAud: "webui"},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			s.seedRefresh(publicRT, "ui")
			s.seedRefresh(confRT, "webui")

			f := url.Values{}
			f.Set("grant_type", "refresh_token")
			f.Set("refresh_token", tc.token)
			if tc.formSecret != "" {
				f.Set("client_secret", tc.formSecret)
			}
			var resp *http.Response
			if tc.basic {
				resp = s.postBasic(f, tc.clientID, tc.basicPass)
			} else {
				if tc.clientID != "" {
					f.Set("client_id", tc.clientID)
				}
				resp = s.post(f)
			}
			defer resp.Body.Close()

			s.Require().Equal(tc.wantStatus, resp.StatusCode)
			if tc.wantErr != "" {
				s.Equal(tc.wantErr, s.decodeOAuthError(resp))
				s.True(s.store.hasRefresh(tc.token), "a rejected refresh must not consume the token")
				return
			}
			body := s.decodeTokenResponse(resp)
			tok, err := s.verifier.Verify(context.Background(), body.AccessToken)
			s.Require().NoError(err)
			clientID, err := jwxjwt.Get[string](tok, "client_id")
			s.Require().NoError(err)
			s.Equal(tc.wantAud, clientID, "the token must stay issued to the client the refresh token was issued to")
			aud, _ := s.parseIDToken(body.IDToken).Audience()
			s.Equal([]string{tc.wantAud}, aud, "the ID token's aud must stay that client")
			s.Equal(tc.wantAud, s.store.lastRefresh().ClientID, "the rotated token must stay bound to the same client")
			s.False(s.store.hasRefresh(tc.token), "a successful refresh consumes the token")
		})
	}
}

// TestRejectedRefreshLeavesTokenForLegitimateClient walks the PoC end to end:
// another client's attempt fails, then the real client still refreshes.
func (s *TokenSuite) TestRejectedRefreshLeavesTokenForLegitimateClient() {
	s.seedRefresh("rt-conf", "webui")

	f := url.Values{}
	f.Set("grant_type", "refresh_token")
	f.Set("refresh_token", "rt-conf")
	f.Set("client_id", "ui")
	stolen := s.post(f)
	defer stolen.Body.Close()
	s.Require().Equal(http.StatusBadRequest, stolen.StatusCode)
	s.Equal("invalid_grant", s.decodeOAuthError(stolen))

	f.Del("client_id")
	resp := s.postBasic(f, "webui", confidentialSecret)
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode)
}

func (s *TokenSuite) seedRefresh(token, clientID string) {
	s.store.putRefresh(oidc.Refresh{
		Token: token, JTI: "jti-" + token, ClientID: clientID, ConnectorID: "google", Subject: "google-sub-alice", Email: "alice@example.com",
		FamilyID: "family-" + token, AuthTime: signNow,
		CreatedAt: signNow, ExpiresAt: signNow.Add(time.Hour),
	})
}

// TestRefreshForARemovedConnectorRevokesTheFamily: a session whose
// connector is no longer configured has nobody left to vouch for it, so the
// refresh is refused and the whole family revoked, and it stays revoked if a
// connector with that id comes back.
func (s *TokenSuite) TestRefreshForARemovedConnectorRevokesTheFamily() {
	s.store.putRefresh(oidc.Refresh{
		Token: "rt-okta", JTI: "jti-okta", ClientID: "ui", ConnectorID: "okta", Subject: "okta-sub-alice", Email: "alice@example.com",
		FamilyID: "family-okta", AuthTime: signNow, CreatedAt: signNow, ExpiresAt: signNow.Add(time.Hour),
	})

	resp := s.post(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"rt-okta"}, "client_id": {"ui"}})
	defer resp.Body.Close()

	s.Equal(http.StatusBadRequest, resp.StatusCode)
	s.Equal("invalid_grant", s.decodeOAuthError(resp))
	s.Equal([]string{"refresh_connector_removed"}, s.observed.revocationCalls())
	s.True(s.store.revokedFamilies["family-okta"])
	s.Contains(s.logs.String(), "event=refresh_connector_removed")
	s.Contains(s.logs.String(), "family_id=family-okta")
}

func (s *TokenSuite) TestRevokeFailureOnConnectorRefusalIsServerError() {
	s.store.putRefresh(oidc.Refresh{
		Token: "rt-okta", JTI: "jti-okta", ClientID: "ui", ConnectorID: "okta", Subject: "okta-sub-alice", Email: "alice@example.com",
		FamilyID: "family-okta", AuthTime: signNow, CreatedAt: signNow, ExpiresAt: signNow.Add(time.Hour),
	})
	s.store.revokeErr = errors.New("db exploded")

	resp := s.post(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"rt-okta"}, "client_id": {"ui"}})
	defer resp.Body.Close()
	s.Equal(http.StatusInternalServerError, resp.StatusCode)
}

// TestRefreshWithoutConnectorsIsRefused: a Token built without the
// configured connectors cannot tell a live connector from a removed one, so
// it fails closed.
func (s *TokenSuite) TestRefreshWithoutConnectorsIsRefused() {
	s.seedRefresh("rt-1", "ui")
	tok := oidc.NewToken(s.store, nil, s.clients, oidc.WithPermissionResolver(permitAll), oidc.WithAllowedDomains("example.com"),
		oidc.WithTokenClock(func() time.Time { return signNow }))
	mux := http.NewServeMux()
	tok.Register(humago.New(mux, huma.DefaultConfig("test", "0.0.0")))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.PostForm(srv.URL+"/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"rt-1"}, "client_id": {"ui"}})
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusBadRequest, resp.StatusCode)
	s.Equal("invalid_grant", s.decodeOAuthError(resp))
}
