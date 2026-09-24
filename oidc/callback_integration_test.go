package oidc_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/suite"

	"github.com/onhotpath/tempogate/oidc"
	"github.com/onhotpath/tempogate/oidc/google"
)

const mockKID = "mock-google-key-1"

// mockGoogle is a minimal but real OIDC IdP: discovery + JWKS + a token
// endpoint that returns a properly RS256-signed id_token. It lets the
// integration test drive oidc.NewGoogleUpstream's real golang.org/x/oauth2 +
// coreos/go-oidc code path without reaching the internet.
type mockGoogle struct {
	srv      *httptest.Server
	clientID string
	priv     *rsa.PrivateKey
	email    string
	verified bool
}

func newMockGoogle(t *testing.T, clientID, email string, verified bool) *mockGoogle {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	mg := &mockGoogle{clientID: clientID, priv: priv, email: email, verified: verified}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", mg.discovery)
	mux.HandleFunc("/jwks", mg.jwks)
	mux.HandleFunc("/token", mg.token)
	mg.srv = httptest.NewServer(mux)
	t.Cleanup(mg.srv.Close)
	return mg
}

func (mg *mockGoogle) issuer() string { return mg.srv.URL }

func (mg *mockGoogle) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"issuer":                                mg.issuer(),
		"authorization_endpoint":                mg.issuer() + "/auth",
		"token_endpoint":                        mg.issuer() + "/token",
		"jwks_uri":                              mg.issuer() + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (mg *mockGoogle) jwks(w http.ResponseWriter, _ *http.Request) {
	pub, err := jwk.Import[jwk.Key](mg.priv.Public())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = pub.Set(jwk.KeyIDKey, mockKID)
	_ = pub.Set(jwk.AlgorithmKey, jwa.RS256())
	_ = pub.Set(jwk.KeyUsageKey, "sig")

	set := jwk.NewSet()
	_ = set.AddKey(pub)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(set)
}

func (mg *mockGoogle) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || r.Form.Get("code") == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}

	priv, err := jwk.Import[jwk.Key](mg.priv)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = priv.Set(jwk.KeyIDKey, mockKID)
	_ = priv.Set(jwk.AlgorithmKey, jwa.RS256())

	now := time.Now()
	tok, err := jwt.NewBuilder().
		Issuer(mg.issuer()).
		Audience([]string{mg.clientID}).
		Subject("google-sub-123").
		IssuedAt(now).
		Expiration(now.Add(time.Hour)).
		Claim("email", mg.email).
		Claim("email_verified", mg.verified).
		Build()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), priv))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]any{
		"access_token": "mock-access-token",
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     string(signed),
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

type CallbackIntegrationSuite struct {
	suite.Suite
	client *http.Client
}

func TestCallbackIntegrationSuite(t *testing.T) {
	suite.Run(t, new(CallbackIntegrationSuite))
}

func (s *CallbackIntegrationSuite) SetupTest() {
	s.client = &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (s *CallbackIntegrationSuite) serverFor(store oidc.CallbackStore, mg *mockGoogle) *httptest.Server {
	up := google.New(
		mg.clientID,
		"mock-secret",
		mg.issuer()+"/token",
		testIssuer+oidc.CallbackPath,
		mg.issuer(),
	)
	c := oidc.NewCallback(store, up, "example.com",
		oidc.WithCallbackClock(func() time.Time { return time.Now().UTC() }),
		oidc.WithCodeGenerator(func() (string, error) { return fixedCode, nil }),
	)
	mux := http.NewServeMux()
	c.Register(humago.New(mux, huma.DefaultConfig("test", "0.0.0")))
	srv := httptest.NewServer(mux)
	s.T().Cleanup(srv.Close)
	return srv
}

func (s *CallbackIntegrationSuite) pending(state string) oidc.AuthRequest {
	now := time.Now().UTC()
	return oidc.AuthRequest{
		InternalState:       state,
		ClientID:            "ui",
		RedirectURI:         testRedirectURI,
		Scope:               "openid email",
		ClientState:         "client-state-abc",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
		CreatedAt:           now,
		ExpiresAt:           now.Add(5 * time.Minute),
	}
}

func (s *CallbackIntegrationSuite) TestRealGoogleFlowMintsCode() {
	mg := newMockGoogle(s.T(), testGoogleCID, "alice@example.com", true)
	store := newMemCallbackStore()
	store.put(s.pending(fixedState))
	srv := s.serverFor(store, mg)

	resp, err := s.client.Get(srv.URL + "/callback/google?code=real-google-code&state=" + fixedState)
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Require().Equal(http.StatusFound, resp.StatusCode)
	loc, err := url.Parse(resp.Header.Get("Location"))
	s.Require().NoError(err)
	s.Equal(fixedCode, loc.Query().Get("code"))
	s.Equal("client-state-abc", loc.Query().Get("state"))

	s.Require().Equal(1, store.codeCount())
	s.Equal("alice@example.com", store.only().Email)
}

func (s *CallbackIntegrationSuite) TestRealGoogleFlowRejectsDisallowedDomain() {
	mg := newMockGoogle(s.T(), testGoogleCID, "intruder@notallowed.com", true)
	store := newMemCallbackStore()
	store.put(s.pending(fixedState))
	srv := s.serverFor(store, mg)

	resp, err := s.client.Get(srv.URL + "/callback/google?code=real-google-code&state=" + fixedState)
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Equal(http.StatusForbidden, resp.StatusCode)
	s.Zero(store.codeCount())
}
