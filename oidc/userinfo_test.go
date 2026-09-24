package oidc_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/stretchr/testify/suite"

	"github.com/onhotpath/tempogate/keys"
	"github.com/onhotpath/tempogate/oidc"
)

type UserInfoSuite struct {
	suite.Suite

	keys   *keys.Keys
	signer *keys.Signer
	srv    *httptest.Server
}

func TestUserInfoSuite(t *testing.T) {
	suite.Run(t, new(UserInfoSuite))
}

func (s *UserInfoSuite) SetupTest() {
	s.keys = keys.New(keys.WithStore(&memKeyStore{}), keys.WithGenerateOptions(keys.WithRSABits(2048)))
	s.Require().NoError(s.keys.Init(context.Background()))
	s.signer = keys.NewSigner(keys.WithKeys(s.keys), keys.WithIssuer(testIssuer))

	verifier := keys.NewVerifier(keys.WithKeys(s.keys), keys.WithIssuer(testIssuer))
	mux := http.NewServeMux()
	oidc.NewUserInfo(verifier).Register(humago.New(mux, huma.DefaultConfig("test", "0.0.0")))
	s.srv = httptest.NewServer(mux)
}

func (s *UserInfoSuite) TearDownTest() {
	s.srv.Close()
}

// mint signs a token directly via the Signer — the handler only ever sees a
// minted JWT, so unit-isolating it from the /token endpoint is faithful.
func (s *UserInfoSuite) mint(req keys.MintRequest) string {
	signed, _, err := s.signer.Mint(context.Background(), req)
	s.Require().NoError(err)
	return signed
}

func (s *UserInfoSuite) get(authHeader string) *http.Response {
	r, err := http.NewRequest(http.MethodGet, s.srv.URL+"/userinfo", http.NoBody)
	s.Require().NoError(err)
	if authHeader != "" {
		r.Header.Set("Authorization", authHeader)
	}
	resp, err := http.DefaultClient.Do(r)
	s.Require().NoError(err)
	return resp
}

func (s *UserInfoSuite) decodeBody(resp *http.Response) map[string]any {
	var m map[string]any
	s.Require().NoError(json.NewDecoder(resp.Body).Decode(&m))
	return m
}

func (s *UserInfoSuite) TestValidBearerReturnsClaims() {
	tok := s.mint(keys.MintRequest{
		Subject: "alice@example.com",
		Email:   "alice@example.com",
		TTL:     time.Hour,
	})

	resp := s.get("Bearer " + tok)
	defer resp.Body.Close()

	s.Require().Equal(http.StatusOK, resp.StatusCode)
	body := s.decodeBody(resp)
	s.Equal("alice@example.com", body["sub"])
	s.Equal("alice@example.com", body["email"])
	s.Equal(true, body["email_verified"])
	s.Equal("alice", body["name"], "name is the email local-part in v1")
}

func (s *UserInfoSuite) TestSchemeIsCaseInsensitive() {
	tok := s.mint(keys.MintRequest{Subject: "bob@example.com", Email: "bob@example.com", TTL: time.Hour})

	resp := s.get("bEaReR " + tok)
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode)
}

func (s *UserInfoSuite) TestNameFallsBackToSubWhenNoEmailClaim() {
	// Email empty ⇒ Signer omits the email claim; name must fall back.
	tok := s.mint(keys.MintRequest{Subject: "service-account-7", TTL: time.Hour})

	resp := s.get("Bearer " + tok)
	defer resp.Body.Close()

	s.Require().Equal(http.StatusOK, resp.StatusCode)
	body := s.decodeBody(resp)
	s.Equal("service-account-7", body["sub"])
	s.Equal("", body["email"])
	s.Equal("service-account-7", body["name"])
}

func (s *UserInfoSuite) TestExpiredTokenIs401() {
	past := keys.NewSigner(
		keys.WithKeys(s.keys),
		keys.WithIssuer(testIssuer),
		keys.WithTokenClock(func() time.Time { return time.Now().Add(-2 * time.Hour) }),
	)
	signed, _, err := past.Mint(context.Background(), keys.MintRequest{
		Subject: "alice@example.com", Email: "alice@example.com", TTL: time.Hour,
	})
	s.Require().NoError(err)

	resp := s.get("Bearer " + signed)
	defer resp.Body.Close()
	s.Equal(http.StatusUnauthorized, resp.StatusCode)
}

func (s *UserInfoSuite) TestWrongIssuerIs401() {
	other := keys.NewSigner(keys.WithKeys(s.keys), keys.WithIssuer("https://attacker.example"))
	signed, _, err := other.Mint(context.Background(), keys.MintRequest{
		Subject: "alice@example.com", Email: "alice@example.com", TTL: time.Hour,
	})
	s.Require().NoError(err)

	resp := s.get("Bearer " + signed)
	defer resp.Body.Close()
	s.Equal(http.StatusUnauthorized, resp.StatusCode)
}

func (s *UserInfoSuite) TestTokenWithoutSubjectIs401() {
	// Email set but Subject empty: the token verifies, yet there is no
	// identity to describe, so the handler rejects it.
	tok := s.mint(keys.MintRequest{Email: "alice@example.com", TTL: time.Hour})

	resp := s.get("Bearer " + tok)
	defer resp.Body.Close()
	s.Equal(http.StatusUnauthorized, resp.StatusCode)
}

func (s *UserInfoSuite) TestNameUsesWholeEmailWhenNoLocalPartSeparator() {
	tok := s.mint(keys.MintRequest{Subject: "svc-1", Email: "mailbox", TTL: time.Hour})

	resp := s.get("Bearer " + tok)
	defer resp.Body.Close()

	s.Require().Equal(http.StatusOK, resp.StatusCode)
	body := s.decodeBody(resp)
	s.Equal("svc-1", body["sub"])
	s.Equal("mailbox", body["email"])
	s.Equal("mailbox", body["name"], "no '@' ⇒ the whole email is the name")
}

func (s *UserInfoSuite) TestMalformedOrMissingAuthorizationIs401() {
	cases := []struct {
		name   string
		header string
	}{
		{"missing header", ""},
		{"no scheme", "abcdef"},
		{"wrong scheme", "Basic dXNlcjpwYXNz"},
		{"bearer with no token", "Bearer "},
		{"bearer with blank token", "Bearer    "},
		{"garbage token", "Bearer not-a-jwt"},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			resp := s.get(tc.header)
			defer resp.Body.Close()
			s.Equal(http.StatusUnauthorized, resp.StatusCode)
		})
	}
}
