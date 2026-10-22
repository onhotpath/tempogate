package oidc_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
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

// mockGoogle is a minimal but real OIDC IdP: discovery + JWKS + an
// authorization endpoint that requires PKCE and a nonce + a token endpoint
// that checks the code_verifier and returns a properly RS256-signed id_token
// echoing the nonce. It lets the integration test drive the real
// golang.org/x/oauth2 + coreos/go-oidc code path without reaching the
// internet.
type mockGoogle struct {
	srv      *httptest.Server
	clientID string
	priv     *rsa.PrivateKey
	email    string
	verified bool

	mu    sync.Mutex
	codes map[string]mockGrant
}

// mockGrant is what /auth bound a code to.
type mockGrant struct {
	challenge string
	nonce     string
}

func newMockGoogle(t *testing.T, clientID, email string, verified bool) *mockGoogle {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	mg := &mockGoogle{clientID: clientID, priv: priv, email: email, verified: verified, codes: map[string]mockGrant{}}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", mg.discovery)
	mux.HandleFunc("/jwks", mg.jwks)
	mux.HandleFunc("/auth", mg.auth)
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

// auth consents immediately: it binds a fresh code to the request's PKCE
// challenge and nonce and redirects back to the redirect_uri.
func (mg *mockGoogle) auth(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" {
		http.Error(w, "PKCE (S256) and nonce are required", http.StatusBadRequest)
		return
	}
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	code := base64.RawURLEncoding.EncodeToString(b)
	mg.mu.Lock()
	mg.codes[code] = mockGrant{challenge: q.Get("code_challenge"), nonce: q.Get("nonce")}
	mg.mu.Unlock()

	back, err := url.Parse(q.Get("redirect_uri"))
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	bq := back.Query()
	bq.Set("code", code)
	bq.Set("state", q.Get("state"))
	back.RawQuery = bq.Encode()
	http.Redirect(w, r, back.String(), http.StatusFound)
}

// approve follows tempogate's redirect to the mock's /auth and returns the
// code the mock sends back, as the user's consent would.
func (mg *mockGoogle) approve(t *testing.T, upstreamLocation string) string {
	t.Helper()
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := noFollow.Get(upstreamLocation)
	if err != nil {
		t.Fatalf("mock /auth: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("mock /auth: status %d", resp.StatusCode)
	}
	back, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("mock /auth location: %v", err)
	}
	return back.Query().Get("code")
}

func (mg *mockGoogle) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || r.Form.Get("code") == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}
	mg.mu.Lock()
	grant, ok := mg.codes[r.Form.Get("code")]
	delete(mg.codes, r.Form.Get("code"))
	mg.mu.Unlock()
	sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
	if !ok || subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(grant.challenge)) != 1 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
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
		Claim("nonce", grant.nonce).
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

// serverFor mounts /authorize and /callback/google over one store and the
// real Google client pointed at mg.
func (s *CallbackIntegrationSuite) serverFor(store *memCallbackStore, mg *mockGoogle) *httptest.Server {
	up := google.New(
		mg.clientID,
		"mock-secret",
		mg.issuer()+"/token",
		testIssuer+oidc.CallbackPath,
		mg.issuer(),
	)
	binding := newTestBinding(s.T(), testIssuer)
	reg, err := oidc.ParseClientRegistry("ui:" + testRedirectURI)
	s.Require().NoError(err)
	a := oidc.New(store, reg, binding, testIssuer, testGoogleCID, mg.issuer()+"/auth")
	c := oidc.NewCallback(store, up, binding, "example.com",
		oidc.WithCallbackClock(func() time.Time { return time.Now().UTC() }),
		oidc.WithCodeGenerator(func() (string, error) { return fixedCode, nil }),
	)
	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("test", "0.0.0"))
	a.Register(api)
	c.Register(api)
	srv := httptest.NewServer(mux)
	s.T().Cleanup(srv.Close)
	return srv
}

// login plays the browser: /authorize, consent at the mock, then
// /callback/google carrying the binding cookie /authorize set.
func (s *CallbackIntegrationSuite) login(srv *httptest.Server, mg *mockGoogle) *http.Response {
	authResp, err := s.client.Get(srv.URL + "/authorize?" + validParams().Encode())
	s.Require().NoError(err)
	_ = authResp.Body.Close()
	s.Require().Equal(http.StatusFound, authResp.StatusCode)
	toGoogle, err := url.Parse(authResp.Header.Get("Location"))
	s.Require().NoError(err)

	code := mg.approve(s.T(), toGoogle.String())
	req, err := http.NewRequest(http.MethodGet,
		srv.URL+"/callback/google?"+callbackQuery(code, toGoogle.Query().Get("state")).Encode(), http.NoBody)
	s.Require().NoError(err)
	for _, c := range authResp.Cookies() {
		req.AddCookie(c)
	}
	resp, err := s.client.Do(req)
	s.Require().NoError(err)
	return resp
}

func (s *CallbackIntegrationSuite) TestRealGoogleFlowMintsCode() {
	mg := newMockGoogle(s.T(), testGoogleCID, "alice@example.com", true)
	store := newMemCallbackStore()
	srv := s.serverFor(store, mg)

	resp := s.login(srv, mg)
	defer resp.Body.Close()

	s.Require().Equal(http.StatusFound, resp.StatusCode)
	loc, err := url.Parse(resp.Header.Get("Location"))
	s.Require().NoError(err)
	s.Equal(fixedCode, loc.Query().Get("code"))
	s.Equal("client-state-abc", loc.Query().Get("state"))

	s.Require().Equal(1, store.codeCount())
	s.Equal("alice@example.com", store.only().Email)
	s.Equal("google-sub-123", store.only().Subject)
}

func (s *CallbackIntegrationSuite) TestRealGoogleFlowRejectsDisallowedDomain() {
	mg := newMockGoogle(s.T(), testGoogleCID, "intruder@notallowed.com", true)
	store := newMemCallbackStore()
	srv := s.serverFor(store, mg)

	resp := s.login(srv, mg)
	defer resp.Body.Close()

	s.Equal(http.StatusForbidden, resp.StatusCode)
	s.Zero(store.codeCount())
}
