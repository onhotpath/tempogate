package oidc_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	jwxjwt "github.com/lestrrat-go/jwx/v4/jwt"

	"github.com/onhotpath/tempogate/keys"
	"github.com/onhotpath/tempogate/oidc"
)

// parseIDToken checks the ID token's signature against the suite's keys and
// returns its claims. keys.Verifier refuses ID tokens by design, so the test
// verifies the way a relying party does: signature, then claims.
func (s *TokenSuite) parseIDToken(raw string) jwxjwt.Token {
	s.Require().NotEmpty(raw)
	kp, err := s.keys.Latest()
	s.Require().NoError(err)
	pub, err := jwk.ParseKey(kp.PublicPEM, jwk.WithX509(true))
	s.Require().NoError(err)
	tok, err := jwxjwt.Parse([]byte(raw), jwxjwt.WithKey(jwa.RS256(), pub), jwxjwt.WithValidate(false))
	s.Require().NoError(err)
	return tok
}

// testAccessAudience is the Temporal audience the suite's Signer stamps on
// access tokens (OIDC_ACCESS_TOKEN_AUDIENCE).
const testAccessAudience = "temporal"

var errBoom = errors.New("boom")

func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func jwsType(s *TokenSuite, raw string) string {
	msg, err := jws.Parse([]byte(raw))
	s.Require().NoError(err)
	typ, _ := msg.Signatures()[0].ProtectedHeaders().Type()
	return typ
}

// TestIDTokenIsSeparateFromAccessToken: the access token is what Temporal
// authorizes (permissions, the Temporal audience); the ID token is the
// relying party's proof of login (aud = client, identity claims, nonce) and
// grants nothing.
func (s *TokenSuite) TestIDTokenIsSeparateFromAccessToken() {
	ac := s.authCode("code-1")
	ac.Nonce = "rp-nonce-pkce"
	s.store.putCode(ac)

	resp := s.post(authCodeForm())
	defer resp.Body.Close()
	s.Require().Equal(http.StatusOK, resp.StatusCode)
	body := s.decodeTokenResponse(resp)
	s.NotEqual(body.AccessToken, body.IDToken, "id_token and access_token must be distinct tokens")

	access, err := s.verifier.Verify(context.Background(), body.AccessToken)
	s.Require().NoError(err)
	aud, _ := access.Audience()
	s.Equal([]string{testAccessAudience}, aud, "access token aud is the Temporal audience")
	perms, ok := access.Field("permissions")
	s.Require().True(ok)
	s.Equal([]string{"temporal-system:admin"}, toStringSlice(s.T(), perms))
	clientID, err := jwxjwt.Get[string](access, "client_id")
	s.Require().NoError(err)
	s.Equal("ui", clientID)
	s.False(access.Has("nonce"), "nonce belongs to the ID token")
	s.Equal(keys.AccessTokenType, jwsType(s, body.AccessToken))

	id := s.parseIDToken(body.IDToken)
	s.Equal("JWT", jwsType(s, body.IDToken))
	aud, _ = id.Audience()
	s.Equal([]string{"ui"}, aud, "OIDC Core §2: the ID token's aud is the client_id")
	s.False(id.Has("permissions"), "an ID token must grant nothing at Temporal")
	nonce, err := jwxjwt.Get[string](id, "nonce")
	s.Require().NoError(err)
	s.Equal("rp-nonce-pkce", nonce)
	sub, _ := id.Subject()
	s.Equal("google:google-sub-alice", sub)
	verified, err := jwxjwt.Get[bool](id, "email_verified")
	s.Require().NoError(err)
	s.True(verified)
	authTime, err := jwxjwt.Get[float64](id, "auth_time")
	s.Require().NoError(err)
	s.Equal(float64(signNow.Unix()), authTime)
	exp, _ := id.Expiration()
	s.Equal(signNow.Add(oidc.IDTokenTTL), exp, "the ID token is short-lived: it is only for the login")
	s.Less(oidc.IDTokenTTL, oidc.DefaultAccessTokenTTL)

	// The ID token is refused where an access token is required.
	_, err = s.verifier.Verify(context.Background(), body.IDToken)
	s.Require().Error(err)
}

// TestRefreshIDTokenKeepsAuthTimeAndDropsNonce: OIDC Core §12.2. A refreshed
// ID token names the same client and the original authentication time, and
// carries no nonce.
func (s *TokenSuite) TestRefreshIDTokenKeepsAuthTimeAndDropsNonce() {
	authTime := signNow.Add(-time.Hour)
	s.store.putRefresh(oidc.Refresh{
		Token: "rt-1", ClientID: "ui", ConnectorID: "google", Subject: "google-sub-alice", Email: "alice@example.com",
		FamilyID: "fam-1", AuthTime: authTime,
		CreatedAt: authTime, ExpiresAt: signNow.Add(time.Hour),
	})
	resp := s.post(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"rt-1"}, "client_id": {"ui"}})
	defer resp.Body.Close()
	s.Require().Equal(http.StatusOK, resp.StatusCode)
	body := s.decodeTokenResponse(resp)

	id := s.parseIDToken(body.IDToken)
	aud, _ := id.Audience()
	s.Equal([]string{"ui"}, aud)
	s.False(id.Has("nonce"))
	at, err := jwxjwt.Get[float64](id, "auth_time")
	s.Require().NoError(err)
	s.Equal(float64(authTime.Unix()), at)
}

// TestMalformedCodeVerifierIsInvalidRequest: RFC 7636 §4.1 fixes the
// verifier at 43-128 characters from the unreserved set. A malformed one is a
// malformed request (RFC 6749 §5.2 invalid_request) and is rejected before
// the code is consumed, so it cannot burn the legitimate client's code.
func (s *TokenSuite) TestMalformedCodeVerifierIsInvalidRequest() {
	cases := []struct{ name, verifier string }{
		{"too short", strings.Repeat("a", 42)},
		{"too long", strings.Repeat("a", 129)},
		{"reserved character", strings.Repeat("a", 42) + "+"},
		{"space", strings.Repeat("a", 42) + " "},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			s.store.putCode(s.authCode("code-1"))
			f := authCodeForm()
			f.Set("code_verifier", tc.verifier)
			resp := s.post(f)
			defer resp.Body.Close()
			s.Equal(http.StatusBadRequest, resp.StatusCode)
			s.Equal("invalid_request", s.decodeOAuthError(resp))

			// The code survived: the real verifier still redeems it.
			ok := s.post(authCodeForm())
			defer ok.Body.Close()
			s.Equal(http.StatusOK, ok.StatusCode)
		})
	}
}

// TestCodeVerifierBoundaryLengthsAreAccepted pins the inclusive bounds and
// the full unreserved alphabet.
func (s *TokenSuite) TestCodeVerifierBoundaryLengthsAreAccepted() {
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
	for _, v := range []string{alphabet[:43], strings.Repeat(alphabet, 2)[:128]} {
		ac := s.authCode("code-1")
		ac.CodeChallenge = s256(v)
		s.store.putCode(ac)
		f := authCodeForm()
		f.Set("code_verifier", v)
		resp := s.post(f)
		s.Equal(http.StatusOK, resp.StatusCode, "verifier of length %d", len(v))
		resp.Body.Close()
	}
}

// TestAuthCodeReplayRevokesIssuedTokens: RFC 6749 §4.1.2 - a code presented
// twice is refused, and the tokens already issued from it are revoked, since
// one of the two presenters is not the client.
func (s *TokenSuite) TestAuthCodeReplayRevokesIssuedTokens() {
	s.store.putCode(s.authCode("code-1"))
	first := s.post(authCodeForm())
	s.Require().Equal(http.StatusOK, first.StatusCode)
	issued := s.decodeTokenResponse(first)
	first.Body.Close()
	s.Require().True(s.store.hasRefresh(issued.RefreshToken))

	replay := s.post(authCodeForm())
	defer replay.Body.Close()
	s.Equal(http.StatusBadRequest, replay.StatusCode)
	s.Equal("invalid_grant", s.decodeOAuthError(replay))

	s.False(s.store.hasRefresh(issued.RefreshToken), "the refresh token issued from the replayed code must be revoked")
	refresh := s.post(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {issued.RefreshToken}, "client_id": {"ui"}})
	defer refresh.Body.Close()
	s.Equal("invalid_grant", s.decodeOAuthError(refresh))
}

// TestAuthCodeReplayRevokeFailureIsServerError: a replay whose revocation
// fails must not be reported as a plain invalid_grant, which would hide that
// the issued tokens are still live.
func (s *TokenSuite) TestAuthCodeReplayRevokeFailureIsServerError() {
	s.store.putCode(s.authCode("code-1"))
	first := s.post(authCodeForm())
	s.Require().Equal(http.StatusOK, first.StatusCode)
	first.Body.Close()

	s.store.revokeErr = errBoom
	replay := s.post(authCodeForm())
	defer replay.Body.Close()
	s.Equal(http.StatusInternalServerError, replay.StatusCode)
}

// TestAuthCodeReplayWithoutFamilyRevokesNothing: a tombstone with no family
// recorded must not be turned into a revocation of family "".
func (s *TokenSuite) TestAuthCodeReplayWithoutFamilyRevokesNothing() {
	s.store.putCode(s.authCode("code-1"))
	s.store.consumedCodes["code-1"] = true

	resp := s.post(authCodeForm())
	defer resp.Body.Close()
	s.Equal("invalid_grant", s.decodeOAuthError(resp))
	s.False(s.store.familyRevoked(""))
}
