package google_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/suite"
	"golang.org/x/oauth2"

	"github.com/onhotpath/tempogate/oidc"
	"github.com/onhotpath/tempogate/oidc/google"
)

const (
	testClientID = "client-123.apps.googleusercontent.com"
	testKID      = "google-test-key"
	testVerifier = "test-pkce-verifier-0123456789abcdefghijklmnop"
	testNonce    = "test-upstream-nonce"
)

type idp struct {
	priv         *rsa.PrivateKey
	sub          string
	email        string
	verified     bool
	hd           string
	omitIDToken  bool
	failExchange bool
	discoveryN   int32

	// nonce is echoed into the id_token; empty omits the claim.
	nonce string
	// audience overrides the id_token aud (default testClientID).
	audience string
	// mistypedClaims makes email_verified a string, which fails to decode.
	mistypedClaims bool

	mu          sync.Mutex
	gotVerifier string

	// discoveryDown makes the discovery document answer 503, modelling a
	// transient outage of the IdP's well-known endpoint.
	discoveryDown atomic.Bool
}

func newIDP(t *testing.T) *idp {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	return &idp{priv: priv, sub: "sub-1", email: "user@example.com", verified: true, nonce: testNonce}
}

func (i *idp) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&i.discoveryN, 1)
		if i.discoveryDown.Load() {
			http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, map[string]any{
			"issuer":                                srv.URL,
			"authorization_endpoint":                srv.URL + "/auth",
			"token_endpoint":                        srv.URL + "/token",
			"jwks_uri":                              srv.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		pub, _ := jwk.Import[jwk.Key](i.priv.Public())
		_ = pub.Set(jwk.KeyIDKey, testKID)
		_ = pub.Set(jwk.AlgorithmKey, jwa.RS256())
		set := jwk.NewSet()
		_ = set.AddKey(pub)
		writeJSON(w, set)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		i.mu.Lock()
		i.gotVerifier = r.Form.Get("code_verifier")
		i.mu.Unlock()
		if i.failExchange {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}
		resp := map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 3600}
		if !i.omitIDToken {
			resp["id_token"] = i.signedIDToken(t, srv.URL)
		}
		writeJSON(w, resp)
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func (i *idp) signedIDToken(t *testing.T, issuer string) string {
	t.Helper()
	priv, _ := jwk.Import[jwk.Key](i.priv)
	_ = priv.Set(jwk.KeyIDKey, testKID)
	_ = priv.Set(jwk.AlgorithmKey, jwa.RS256())
	now := time.Now()
	aud := testClientID
	if i.audience != "" {
		aud = i.audience
	}
	var verified any = i.verified
	if i.mistypedClaims {
		verified = "yes"
	}
	b := jwt.NewBuilder().
		Issuer(issuer).
		Audience([]string{aud}).
		IssuedAt(now).
		Expiration(now.Add(time.Hour)).
		Claim("email", i.email).
		Claim("email_verified", verified)
	if i.sub != "" {
		b = b.Subject(i.sub)
	}
	if i.hd != "" {
		b = b.Claim("hd", i.hd)
	}
	if i.nonce != "" {
		b = b.Claim("nonce", i.nonce)
	}
	tok, err := b.Build()
	if err != nil {
		t.Fatalf("build token: %v", err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), priv))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return string(signed)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

type GoogleSuite struct {
	suite.Suite
	ctx context.Context
}

func TestGoogleSuite(t *testing.T) {
	suite.Run(t, new(GoogleSuite))
}

func (s *GoogleSuite) SetupTest() { s.ctx = context.Background() }

func (s *GoogleSuite) clientFor(srv *httptest.Server) *google.Client {
	return google.New(testClientID, "secret", srv.URL+"/token",
		"https://tempogate.example.com/callback/google", srv.URL)
}

func (s *GoogleSuite) TestHappyPath() {
	i := newIDP(s.T())
	srv := i.server(s.T())
	c := s.clientFor(srv)

	id, err := c.ExchangeAndVerify(s.ctx, "code", testVerifier, testNonce)
	s.Require().NoError(err)
	s.Equal("sub-1", id.Subject)
	s.Equal("user@example.com", id.Email)
	s.True(id.EmailVerified)
	s.Empty(id.HostedDomain, "a consumer account carries no hd claim")
}

func (s *GoogleSuite) TestHostedDomainIsDecoded() {
	i := newIDP(s.T())
	i.hd = "example.com"
	srv := i.server(s.T())
	c := s.clientFor(srv)

	id, err := c.ExchangeAndVerify(s.ctx, "code", testVerifier, testNonce)
	s.Require().NoError(err)
	s.Equal("example.com", id.HostedDomain)
}

func (s *GoogleSuite) TestMissingSubjectIsRejected() {
	i := newIDP(s.T())
	i.sub = ""
	srv := i.server(s.T())
	c := s.clientFor(srv)

	_, err := c.ExchangeAndVerify(s.ctx, "code", testVerifier, testNonce)
	s.Require().Error(err)
	s.Contains(err.Error(), "sub")
}

func (s *GoogleSuite) TestMissingEmailIsRejected() {
	i := newIDP(s.T())
	i.email = ""
	srv := i.server(s.T())
	c := s.clientFor(srv)

	_, err := c.ExchangeAndVerify(s.ctx, "code", testVerifier, testNonce)
	s.Require().Error(err)
	s.Contains(err.Error(), "email")
}

func (s *GoogleSuite) TestExchangeFailure() {
	i := newIDP(s.T())
	i.failExchange = true
	srv := i.server(s.T())
	c := s.clientFor(srv)

	_, err := c.ExchangeAndVerify(s.ctx, "code", testVerifier, testNonce)
	s.Require().Error(err)
	s.Contains(err.Error(), "code exchange")
}

func (s *GoogleSuite) TestMissingIDToken() {
	i := newIDP(s.T())
	i.omitIDToken = true
	srv := i.server(s.T())
	c := s.clientFor(srv)

	_, err := c.ExchangeAndVerify(s.ctx, "code", testVerifier, testNonce)
	s.Require().Error(err)
	s.Contains(err.Error(), "missing id_token")
}

func (s *GoogleSuite) TestPKCEVerifierIsSentToTokenEndpoint() {
	i := newIDP(s.T())
	srv := i.server(s.T())
	c := s.clientFor(srv)

	_, err := c.ExchangeAndVerify(s.ctx, "code", testVerifier, testNonce)
	s.Require().NoError(err)
	i.mu.Lock()
	defer i.mu.Unlock()
	s.Equal(testVerifier, i.gotVerifier)
}

func (s *GoogleSuite) TestNonceMismatchIsRejected() {
	cases := map[string]string{
		"different nonce": "attacker-nonce",
		"no nonce claim":  "",
	}
	for name, nonce := range cases {
		s.Run(name, func() {
			i := newIDP(s.T())
			i.nonce = nonce
			srv := i.server(s.T())
			c := s.clientFor(srv)

			_, err := c.ExchangeAndVerify(s.ctx, "code", testVerifier, testNonce)
			s.Require().Error(err)
			s.Equal(oidc.UpstreamReasonNonce, reasonOf(err))
		})
	}
}

func (s *GoogleSuite) TestFailuresCarryAReason() {
	cases := []struct {
		name   string
		mutate func(*idp)
		reason string
	}{
		{"token endpoint rejects the code", func(i *idp) { i.failExchange = true }, oidc.UpstreamReasonExchange},
		{"token response without id_token", func(i *idp) { i.omitIDToken = true }, oidc.UpstreamReasonIDToken},
		{"id_token for another client", func(i *idp) { i.audience = "someone-else" }, oidc.UpstreamReasonIDToken},
		{"id_token claims of the wrong type", func(i *idp) { i.mistypedClaims = true }, oidc.UpstreamReasonIDToken},
		{"id_token without sub", func(i *idp) { i.sub = "" }, oidc.UpstreamReasonClaims},
		{"id_token without email", func(i *idp) { i.email = "" }, oidc.UpstreamReasonClaims},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			i := newIDP(s.T())
			tc.mutate(i)
			srv := i.server(s.T())
			c := s.clientFor(srv)

			_, err := c.ExchangeAndVerify(s.ctx, "code", testVerifier, testNonce)
			s.Require().Error(err)
			s.Equal(tc.reason, reasonOf(err))
		})
	}
}

func (s *GoogleSuite) TestExchangeFailureCarriesOAuthErrorCode() {
	i := newIDP(s.T())
	i.failExchange = true
	srv := i.server(s.T())
	c := s.clientFor(srv)

	_, err := c.ExchangeAndVerify(s.ctx, "code", testVerifier, testNonce)
	var ue *oidc.UpstreamError
	s.Require().ErrorAs(err, &ue)
	s.Equal("invalid_grant", ue.OAuthError)
	var re *oauth2.RetrieveError
	s.Require().ErrorAs(err, &re, "the cause stays reachable through the UpstreamError")
}

// TestDiscoveryRecoversAfterTransientFailure is the regression for a
// discovery failure on first use being cached until restart: one outage of
// the IdP's well-known endpoint must not break every later login. Retries
// are spaced by a growing backoff, so a hard outage cannot turn each
// callback into a discovery request.
func (s *GoogleSuite) TestDiscoveryRecoversAfterTransientFailure() {
	i := newIDP(s.T())
	srv := i.server(s.T())
	t0 := time.Unix(1700000000, 0)
	now := t0
	c := google.New(testClientID, "secret", srv.URL+"/token",
		"https://tempogate.example.com/callback/google", srv.URL,
		google.WithClock(func() time.Time { return now }))
	discoveries := func() int32 { return atomic.LoadInt32(&i.discoveryN) }

	i.discoveryDown.Store(true)
	_, err := c.ExchangeAndVerify(s.ctx, "code", testVerifier, testNonce)
	s.Require().Error(err)
	s.Equal(oidc.UpstreamReasonDiscovery, reasonOf(err))
	s.EqualValues(1, discoveries())

	now = t0.Add(500 * time.Millisecond)
	_, err = c.ExchangeAndVerify(s.ctx, "code", testVerifier, testNonce)
	s.Equal(oidc.UpstreamReasonDiscovery, reasonOf(err))
	s.EqualValues(1, discoveries(), "inside the backoff window the failure is served without a request")

	now = t0.Add(time.Second)
	_, err = c.ExchangeAndVerify(s.ctx, "code", testVerifier, testNonce)
	s.Equal(oidc.UpstreamReasonDiscovery, reasonOf(err))
	s.EqualValues(2, discoveries(), "the backoff window elapsed, so discovery is retried")

	i.discoveryDown.Store(false)
	now = t0.Add(2500 * time.Millisecond)
	_, err = c.ExchangeAndVerify(s.ctx, "code", testVerifier, testNonce)
	s.Equal(oidc.UpstreamReasonDiscovery, reasonOf(err))
	s.EqualValues(2, discoveries(), "the backoff doubled after the second failure")

	now = t0.Add(3 * time.Second)
	id, err := c.ExchangeAndVerify(s.ctx, "code", testVerifier, testNonce)
	s.Require().NoError(err, "discovery recovers once the IdP is back, without a restart")
	s.Equal("sub-1", id.Subject)
	s.EqualValues(3, discoveries())

	_, err = c.ExchangeAndVerify(s.ctx, "code", testVerifier, testNonce)
	s.Require().NoError(err)
	s.EqualValues(3, discoveries(), "a successful discovery is cached")
}

func (s *GoogleSuite) TestDiscoveryBackoffIsCapped() {
	i := newIDP(s.T())
	srv := i.server(s.T())
	now := time.Unix(1700000000, 0)
	c := google.New(testClientID, "secret", srv.URL+"/token",
		"https://tempogate.example.com/callback/google", srv.URL,
		google.WithClock(func() time.Time { return now }))
	i.discoveryDown.Store(true)

	// Fail an hour apart, so every call retries and the backoff keeps
	// doubling well past any sane cap.
	for range 12 {
		_, err := c.ExchangeAndVerify(s.ctx, "code", testVerifier, testNonce)
		s.Require().Error(err)
		now = now.Add(time.Hour)
	}
	n := atomic.LoadInt32(&i.discoveryN)

	i.discoveryDown.Store(false)
	now = now.Add(time.Minute)
	_, err := c.ExchangeAndVerify(s.ctx, "code", testVerifier, testNonce)
	s.Require().NoError(err, "after a long outage, recovery is at most a minute away")
	s.EqualValues(n+1, atomic.LoadInt32(&i.discoveryN))
}

func reasonOf(err error) string {
	var ue *oidc.UpstreamError
	if errors.As(err, &ue) {
		return ue.Reason
	}
	return ""
}
