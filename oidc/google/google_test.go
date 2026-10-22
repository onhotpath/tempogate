package google_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/suite"

	"github.com/onhotpath/tempogate/oidc/google"
)

const (
	testClientID = "client-123.apps.googleusercontent.com"
	testKID      = "google-test-key"
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
}

func newIDP(t *testing.T) *idp {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	return &idp{priv: priv, sub: "sub-1", email: "user@example.com", verified: true}
}

func (i *idp) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&i.discoveryN, 1)
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
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		if i.failExchange {
			http.Error(w, "nope", http.StatusBadRequest)
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
	b := jwt.NewBuilder().
		Issuer(issuer).
		Audience([]string{testClientID}).
		IssuedAt(now).
		Expiration(now.Add(time.Hour)).
		Claim("email", i.email).
		Claim("email_verified", i.verified)
	if i.sub != "" {
		b = b.Subject(i.sub)
	}
	if i.hd != "" {
		b = b.Claim("hd", i.hd)
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

	id, err := c.ExchangeAndVerify(s.ctx, "code")
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

	id, err := c.ExchangeAndVerify(s.ctx, "code")
	s.Require().NoError(err)
	s.Equal("example.com", id.HostedDomain)
}

func (s *GoogleSuite) TestMissingSubjectIsRejected() {
	i := newIDP(s.T())
	i.sub = ""
	srv := i.server(s.T())
	c := s.clientFor(srv)

	_, err := c.ExchangeAndVerify(s.ctx, "code")
	s.Require().Error(err)
	s.Contains(err.Error(), "sub")
}

func (s *GoogleSuite) TestMissingEmailIsRejected() {
	i := newIDP(s.T())
	i.email = ""
	srv := i.server(s.T())
	c := s.clientFor(srv)

	_, err := c.ExchangeAndVerify(s.ctx, "code")
	s.Require().Error(err)
	s.Contains(err.Error(), "email")
}

func (s *GoogleSuite) TestExchangeFailure() {
	i := newIDP(s.T())
	i.failExchange = true
	srv := i.server(s.T())
	c := s.clientFor(srv)

	_, err := c.ExchangeAndVerify(s.ctx, "code")
	s.Require().Error(err)
	s.Contains(err.Error(), "code exchange")
}

func (s *GoogleSuite) TestMissingIDToken() {
	i := newIDP(s.T())
	i.omitIDToken = true
	srv := i.server(s.T())
	c := s.clientFor(srv)

	_, err := c.ExchangeAndVerify(s.ctx, "code")
	s.Require().Error(err)
	s.Contains(err.Error(), "missing id_token")
}

func (s *GoogleSuite) TestDiscoveryFailureIsCached() {
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": "x"})
	})
	// no discovery handler: NewProvider 404s.
	srv := httptest.NewServer(mux)
	s.T().Cleanup(srv.Close)

	c := google.New(testClientID, "secret", srv.URL+"/token",
		"https://tempogate.example.com/callback/google", srv.URL)

	_, err1 := c.ExchangeAndVerify(s.ctx, "code")
	s.Require().Error(err1)
	s.Contains(err1.Error(), "discovery")

	_, err2 := c.ExchangeAndVerify(s.ctx, "code")
	s.Require().Error(err2)
	s.Contains(err2.Error(), "discovery")
}
