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

	"github.com/onhotpath/tempogate/oidc"
)

// The authz tests drive the shared TokenSuite (its resolver grants
// temporal-system:admin unless a test narrows or denies it).

func (s *TokenSuite) permissionsOf(accessToken string) []string {
	tok, err := s.verifier.Verify(context.Background(), accessToken)
	s.Require().NoError(err)
	perms, ok := tok.Field("permissions")
	s.Require().True(ok)
	return toStringSlice(s.T(), perms)
}

func (s *TokenSuite) TestAccessTokenCarriesTheResolvedPermissions() {
	s.resolver.grant = newStubResolver("ns-a:read", "ns-b:write").grant
	s.store.putCode(s.authCode("code-1"))

	resp := s.post(authCodeForm())
	defer resp.Body.Close()
	s.Require().Equal(http.StatusOK, resp.StatusCode)
	body := s.decodeTokenResponse(resp)

	s.Equal([]string{"ns-a:read", "ns-b:write"}, s.permissionsOf(body.AccessToken))
	s.Equal([]string{"alice@example.com"}, s.resolver.calls(), "resolved from the signed-in email")
}

func (s *TokenSuite) TestCodeGrantWithNoPermissionsIsInvalidGrantAndMintsNothing() {
	s.resolver.denyEmail("alice@example.com")
	s.store.putCode(s.authCode("code-1"))

	resp := s.post(authCodeForm())
	defer resp.Body.Close()
	s.Equal(http.StatusBadRequest, resp.StatusCode)
	s.Equal("invalid_grant", s.decodeOAuthError(resp))
	s.Equal(0, s.store.refreshCount(), "no refresh token is persisted")
	s.Equal([]string{"authorization_code"}, s.observed.denials())
	s.Contains(s.logs.String(), "event=token_authz_denied")
	s.Contains(s.logs.String(), "email=alice@example.com")
}

func (s *TokenSuite) seedAliceRefresh() url.Values {
	s.store.putRefresh(oidc.Refresh{
		Token:     "old-refresh",
		JTI:       "old-jti",
		ClientID:  "ui",
		Subject:   "google-sub-alice",
		Email:     "alice@example.com",
		FamilyID:  "fam-1",
		AuthTime:  signNow,
		CreatedAt: signNow,
		ExpiresAt: signNow.Add(7 * 24 * time.Hour),
	})
	f := url.Values{}
	f.Set("grant_type", "refresh_token")
	f.Set("refresh_token", "old-refresh")
	f.Set("client_id", "ui")
	return f
}

func (s *TokenSuite) TestRefreshRecomputesPermissions() {
	f := s.seedAliceRefresh()
	// The rule changed since sign-in: the refreshed token carries the new
	// grant, not the one minted at sign-in.
	s.resolver.grant = newStubResolver("ns-b:write").grant

	resp := s.post(f)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusOK, resp.StatusCode)
	s.Equal([]string{"ns-b:write"}, s.permissionsOf(s.decodeTokenResponse(resp).AccessToken))
	s.False(s.store.familyRevoked("fam-1"))
}

func (s *TokenSuite) TestRefreshWithNoPermissionsRevokesTheFamily() {
	f := s.seedAliceRefresh()
	s.resolver.denyEmail("alice@example.com")

	resp := s.post(f)
	defer resp.Body.Close()
	s.Equal(http.StatusBadRequest, resp.StatusCode)
	s.Equal("invalid_grant", s.decodeOAuthError(resp))
	s.True(s.store.familyRevoked("fam-1"), "a person no longer granted anything loses the session")
	s.Equal(0, s.store.refreshCount(), "nothing rotated")
	s.Equal([]string{"refresh_authz_denied"}, s.observed.revocations)
	s.Equal([]string{"refresh_token"}, s.observed.denials())
	logs := s.logs.String()
	s.Contains(logs, "level=WARN")
	s.Contains(logs, "event=refresh_authz_denied")
	s.Contains(logs, "family_id=fam-1")
}

func (s *TokenSuite) TestDeviceGrantWithNoPermissionsIsAccessDenied() {
	s.seedPending("dc-1", "WDJBMJHT")
	s.approve("WDJBMJHT", aliceID())
	s.resolver.denyEmail("alice@example.com")

	resp := s.post(deviceForm("dc-1", "tempogate-device"))
	defer resp.Body.Close()
	s.Equal(http.StatusBadRequest, resp.StatusCode)
	s.Equal("access_denied", s.decodeOAuthError(resp))
	s.Equal([]string{"device_code"}, s.observed.denials())
	s.Equal(0, s.store.refreshCount())
}

func (s *TokenSuite) TestResolverFailureIsServerErrorAndMintsNothing() {
	s.resolver.err = errors.New("directory unavailable")
	s.store.putCode(s.authCode("code-1"))

	resp := s.post(authCodeForm())
	defer resp.Body.Close()
	s.Equal(http.StatusInternalServerError, resp.StatusCode)
	s.Equal(0, s.store.refreshCount())
	s.Empty(s.observed.denials(), "an outage is not a denial")
}

func (s *TokenSuite) TestTokenWithoutResolverDeniesEveryone() {
	// No WithPermissionResolver: fail closed. The nil signer is never
	// reached, which is the point.
	tok := oidc.NewToken(s.store, nil, s.clients)
	mux := http.NewServeMux()
	tok.Register(humago.New(mux, huma.DefaultConfig("test", "0.0.0")))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	s.store.putCode(s.authCode("code-1"))
	resp, err := http.PostForm(srv.URL+oidc.TokenPath, authCodeForm())
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusBadRequest, resp.StatusCode)
	s.Equal("invalid_grant", s.decodeOAuthError(resp))
}
