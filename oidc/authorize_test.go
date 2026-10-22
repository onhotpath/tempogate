package oidc_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/stretchr/testify/suite"

	"github.com/onhotpath/tempogate/oidc"
)

const (
	testIssuer      = "https://tempogate.example.com"
	testGoogleAuth  = "https://accounts.google.com/o/oauth2/v2/auth"
	testGoogleCID   = "google-client-123.apps.googleusercontent.com"
	testRedirectURI = "https://app.example.com/auth/callback"
	fixedState      = "fixed-internal-state"
)

var fixedNow = time.Unix(1700000000, 0).UTC()

// memAuthStore satisfies oidc.AuthRequestStore structurally — the
// consumer-side interface convention means oidc_test owns its own stub.
type memAuthStore struct {
	mu      sync.Mutex
	saved   []oidc.AuthRequest
	saveErr error
}

func (m *memAuthStore) SaveAuthRequest(_ context.Context, ar oidc.AuthRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.saveErr != nil {
		return m.saveErr
	}
	m.saved = append(m.saved, ar)
	return nil
}

func (m *memAuthStore) only() oidc.AuthRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.saved[len(m.saved)-1]
}

func (m *memAuthStore) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.saved)
}

type AuthorizeSuite struct {
	suite.Suite

	store  *memAuthStore
	srv    *httptest.Server
	client *http.Client
}

func TestAuthorizeSuite(t *testing.T) {
	suite.Run(t, new(AuthorizeSuite))
}

func (s *AuthorizeSuite) SetupTest() {
	s.store = &memAuthStore{}
	s.srv = s.serverFor(s.store,
		oidc.WithClock(func() time.Time { return fixedNow }),
		oidc.WithStateGenerator(func() (string, error) { return fixedState, nil }),
	)
	s.client = &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (s *AuthorizeSuite) TearDownTest() {
	s.srv.Close()
}

func (s *AuthorizeSuite) serverFor(store oidc.AuthRequestStore, opts ...oidc.Option) *httptest.Server {
	reg, err := oidc.ParseClientRegistry("ui:" + testRedirectURI + ",cli:http://127.0.0.1/callback,tempogate-device:")
	s.Require().NoError(err)

	a := oidc.New(store, reg, testIssuer, testGoogleCID, testGoogleAuth, opts...)

	mux := http.NewServeMux()
	a.Register(humago.New(mux, huma.DefaultConfig("test", "0.0.0")))
	return httptest.NewServer(mux)
}

func (s *AuthorizeSuite) get(srv *httptest.Server, q url.Values) *http.Response {
	resp, err := s.client.Get(srv.URL + "/authorize?" + q.Encode())
	s.Require().NoError(err)
	return resp
}

func validParams() url.Values {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", "ui")
	q.Set("redirect_uri", testRedirectURI)
	q.Set("scope", "openid email")
	q.Set("state", "client-state-abc")
	q.Set("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
	q.Set("code_challenge_method", "S256")
	return q
}

func (s *AuthorizeSuite) TestValidRequestRedirectsToGoogle() {
	resp := s.get(s.srv, validParams())
	defer resp.Body.Close()

	s.Equal(http.StatusFound, resp.StatusCode)

	loc, err := url.Parse(resp.Header.Get("Location"))
	s.Require().NoError(err)
	s.Equal("accounts.google.com", loc.Host)
	s.Equal("/o/oauth2/v2/auth", loc.Path)

	q := loc.Query()
	s.Equal(testGoogleCID, q.Get("client_id"))
	s.Equal(testIssuer+"/callback/google", q.Get("redirect_uri"))
	s.Equal("code", q.Get("response_type"))
	s.Equal("openid email", q.Get("scope"))
	s.Equal(fixedState, q.Get("state"))
}

// TestPathIssuerRedirectURICarriesPrefix is the contract that makes sub-path
// hosting work: oidc.New already trims/uses the issuer verbatim, so a
// path-prefixed issuer (e.g. https://h/idp) yields a prefixed Google
// redirect_uri (https://h/idp/callback/google). The Authorizer needs no
// path-awareness of its own — this guards that property from regressing.
func (s *AuthorizeSuite) TestPathIssuerRedirectURICarriesPrefix() {
	reg, err := oidc.ParseClientRegistry("ui:" + testRedirectURI)
	s.Require().NoError(err)
	a := oidc.New(s.store, reg, testIssuer+"/idp", testGoogleCID, testGoogleAuth,
		oidc.WithClock(func() time.Time { return fixedNow }),
		oidc.WithStateGenerator(func() (string, error) { return fixedState, nil }),
	)
	mux := http.NewServeMux()
	a.Register(humago.New(mux, huma.DefaultConfig("test", "0.0.0")))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp := s.get(srv, validParams())
	defer resp.Body.Close()

	s.Equal(http.StatusFound, resp.StatusCode)
	loc, err := url.Parse(resp.Header.Get("Location"))
	s.Require().NoError(err)
	s.Equal(testIssuer+"/idp/callback/google", loc.Query().Get("redirect_uri"),
		"a path-prefixed issuer must yield a prefixed Google redirect_uri")
}

func (s *AuthorizeSuite) TestValidRequestPersistsAuthRequestWithTTL() {
	resp := s.get(s.srv, validParams())
	defer resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)
	s.Require().Equal(1, s.store.count())

	ar := s.store.only()
	s.Equal(fixedState, ar.InternalState)
	s.Equal("ui", ar.ClientID)
	s.Equal(testRedirectURI, ar.RedirectURI)
	s.Equal("openid email", ar.Scope)
	s.Equal("client-state-abc", ar.ClientState)
	s.Equal("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", ar.CodeChallenge)
	s.Equal("S256", ar.CodeChallengeMethod)
	s.True(fixedNow.Equal(ar.CreatedAt))
	s.Equal(5*time.Minute, ar.ExpiresAt.Sub(ar.CreatedAt))
}

// confidentialSrv builds an /authorize server whose registry has `ui` public
// and `webui` confidential (a secret), so the PKCE carve-out can be exercised
// against the same shared store.
func (s *AuthorizeSuite) confidentialSrv() *httptest.Server {
	reg, err := oidc.ParseClientRegistry("ui:" + testRedirectURI + ",webui:" + testRedirectURI)
	s.Require().NoError(err)
	s.Require().NoError(reg.WithSecrets("webui:ui-secret"))

	a := oidc.New(s.store, reg, testIssuer, testGoogleCID, testGoogleAuth,
		oidc.WithClock(func() time.Time { return fixedNow }),
		oidc.WithStateGenerator(func() (string, error) { return fixedState, nil }),
	)
	mux := http.NewServeMux()
	a.Register(humago.New(mux, huma.DefaultConfig("test", "0.0.0")))
	srv := httptest.NewServer(mux)
	s.T().Cleanup(srv.Close)
	return srv
}

func (s *AuthorizeSuite) TestConfidentialClientMayOmitPKCE() {
	srv := s.confidentialSrv()
	q := validParams()
	q.Set("client_id", "webui")
	q.Del("code_challenge")
	q.Del("code_challenge_method")

	resp := s.get(srv, q)
	defer resp.Body.Close()

	s.Require().Equal(http.StatusFound, resp.StatusCode)
	s.Require().Equal(1, s.store.count())
	ar := s.store.only()
	s.Equal("webui", ar.ClientID)
	s.Empty(ar.CodeChallenge, "confidential client completes /authorize with no PKCE challenge")
}

func (s *AuthorizeSuite) TestPublicClientStillRequiresPKCEEvenWhereCarveOutExists() {
	srv := s.confidentialSrv()
	q := validParams() // client_id=ui, which stays public
	q.Del("code_challenge")

	resp := s.get(srv, q)
	defer resp.Body.Close()

	s.assertErrorRedirect(resp, "invalid_request", "client-state-abc")
	s.Zero(s.store.count())
}

func (s *AuthorizeSuite) TestConfidentialClientWithChallengeStillEnforcesS256() {
	srv := s.confidentialSrv()
	q := validParams()
	q.Set("client_id", "webui")
	q.Set("code_challenge_method", "plain")

	resp := s.get(srv, q)
	defer resp.Body.Close()

	// PKCE is still enforced when a confidential client sends a challenge.
	s.assertErrorRedirect(resp, "invalid_request", "client-state-abc")
	s.Zero(s.store.count())
}

// TestLoopbackClientAcceptsAnyPort is the RFC 8252 §7.3 positive case: the
// CLI binds an ephemeral port, so a loopback registration matches the exact
// path on any port, and the requested URI (port included) is what gets bound
// into the AuthRequest.
func (s *AuthorizeSuite) TestLoopbackClientAcceptsAnyPort() {
	q := validParams()
	q.Set("client_id", "cli")
	q.Set("redirect_uri", "http://127.0.0.1:54321/callback")

	resp := s.get(s.srv, q)
	defer resp.Body.Close()

	s.Require().Equal(http.StatusFound, resp.StatusCode)
	s.Require().Equal(1, s.store.count())
	s.Equal("http://127.0.0.1:54321/callback", s.store.only().RedirectURI)
}

func (s *AuthorizeSuite) TestNoncePersistedIntoAuthRequest() {
	q := validParams()
	q.Set("nonce", "rp-nonce-123")

	resp := s.get(s.srv, q)
	defer resp.Body.Close()

	s.Require().Equal(http.StatusFound, resp.StatusCode)
	s.Require().Equal(1, s.store.count())
	s.Equal("rp-nonce-123", s.store.only().Nonce)
}

// TestErrorsBeforeRedirectURIValidationAreShownDirectly: RFC 6749 §4.1.2.1.
// Until client_id and redirect_uri are known good there is nowhere safe to
// send the user agent, so the error is the response itself.
func (s *AuthorizeSuite) TestErrorsBeforeRedirectURIValidationAreShownDirectly() {
	cases := []struct {
		name      string
		mutate    func(url.Values)
		wantError string
	}{
		{
			name:      "unknown client_id",
			mutate:    func(q url.Values) { q.Set("client_id", "ghost") },
			wantError: "invalid_client",
		},
		{
			name:      "redirect_uri not registered",
			mutate:    func(q url.Values) { q.Set("redirect_uri", "https://evil.example.com/cb") },
			wantError: "invalid_request",
		},
		{
			name:      "redirect_uri extends the registered URI (dot segments)",
			mutate:    func(q url.Values) { q.Set("redirect_uri", testRedirectURI+"/../../open-redirect") },
			wantError: "invalid_request",
		},
		{
			name: "loopback redirect_uri hiding another host in userinfo",
			mutate: func(q url.Values) {
				q.Set("client_id", "cli")
				q.Set("redirect_uri", "http://127.0.0.1:@evil.example/callback")
			},
			wantError: "invalid_request",
		},
		{
			name: "device-only client cannot use the authorization-code flow",
			mutate: func(q url.Values) {
				q.Set("client_id", "tempogate-device")
				q.Set("redirect_uri", "http://127.0.0.1:1234/callback")
			},
			wantError: "unauthorized_client",
		},
		{
			name: "invalid redirect_uri wins over a bad response_type",
			mutate: func(q url.Values) {
				q.Set("redirect_uri", "https://evil.example.com/cb")
				q.Set("response_type", "token")
			},
			wantError: "invalid_request",
		},
	}

	for _, tc := range cases {
		s.Run(tc.name, func() {
			q := validParams()
			tc.mutate(q)

			resp := s.get(s.srv, q)
			defer resp.Body.Close()

			s.Equal(http.StatusBadRequest, resp.StatusCode)

			var body struct {
				Error string `json:"error"`
				Desc  string `json:"error_description"`
			}
			s.Require().NoError(json.NewDecoder(resp.Body).Decode(&body))
			s.Equal(tc.wantError, body.Error)
			s.NotEmpty(body.Desc)
			s.Empty(resp.Header.Get("Location"))
			s.Zero(s.store.count())
		})
	}
}

// TestErrorsAfterRedirectURIValidationRedirectToTheClient: RFC 6749
// §4.1.2.1 and RFC 7636 §4.4.1. Once the redirect URI is validated, errors go
// back to the client with its state, and with iss (RFC 9207) so the client
// can tell which authorization server answered.
func (s *AuthorizeSuite) TestErrorsAfterRedirectURIValidationRedirectToTheClient() {
	cases := []struct {
		name      string
		mutate    func(url.Values)
		wantError string
	}{
		{
			name:      "unsupported response_type",
			mutate:    func(q url.Values) { q.Set("response_type", "token") },
			wantError: "unsupported_response_type",
		},
		{
			name:      "missing response_type",
			mutate:    func(q url.Values) { q.Del("response_type") },
			wantError: "unsupported_response_type",
		},
		{
			name:      "scope missing openid",
			mutate:    func(q url.Values) { q.Set("scope", "email profile") },
			wantError: "invalid_scope",
		},
		{
			name:      "missing code_challenge (PKCE required)",
			mutate:    func(q url.Values) { q.Del("code_challenge") },
			wantError: "invalid_request",
		},
		{
			name:      "code_challenge_method not S256",
			mutate:    func(q url.Values) { q.Set("code_challenge_method", "plain") },
			wantError: "invalid_request",
		},
		{
			name:      "code_challenge shorter than 43",
			mutate:    func(q url.Values) { q.Set("code_challenge", strings.Repeat("a", 42)) },
			wantError: "invalid_request",
		},
		{
			name:      "code_challenge longer than 43",
			mutate:    func(q url.Values) { q.Set("code_challenge", strings.Repeat("a", 44)) },
			wantError: "invalid_request",
		},
		{
			name:      "code_challenge not base64url",
			mutate:    func(q url.Values) { q.Set("code_challenge", strings.Repeat("a", 42)+"=") },
			wantError: "invalid_request",
		},
	}

	for _, tc := range cases {
		s.Run(tc.name, func() {
			q := validParams()
			tc.mutate(q)

			resp := s.get(s.srv, q)
			defer resp.Body.Close()

			s.assertErrorRedirect(resp, tc.wantError, "client-state-abc")
			s.Zero(s.store.count())
		})
	}
}

// TestErrorRedirectOmitsAbsentState: state is echoed only when the client
// sent one (RFC 6749 §4.1.2.1).
func (s *AuthorizeSuite) TestErrorRedirectOmitsAbsentState() {
	q := validParams()
	q.Del("state")
	q.Set("response_type", "token")

	resp := s.get(s.srv, q)
	defer resp.Body.Close()

	loc := s.assertErrorRedirect(resp, "unsupported_response_type", "")
	s.False(loc.Query().Has("state"))
}

// assertErrorRedirect checks an RFC 6749 §4.1.2.1 error response and returns
// the parsed Location.
func (s *AuthorizeSuite) assertErrorRedirect(resp *http.Response, wantError, wantState string) *url.URL {
	s.T().Helper()
	s.Require().Equal(http.StatusFound, resp.StatusCode)
	loc, err := url.Parse(resp.Header.Get("Location"))
	s.Require().NoError(err)
	target, _ := url.Parse(testRedirectURI)
	s.Equal(target.Scheme, loc.Scheme)
	s.Equal(target.Host, loc.Host)
	s.Equal(target.Path, loc.Path)
	s.Equal(wantError, loc.Query().Get("error"))
	s.NotEmpty(loc.Query().Get("error_description"))
	s.Equal(wantState, loc.Query().Get("state"))
	s.Equal(testIssuer, loc.Query().Get("iss"))
	s.False(loc.Query().Has("code"))
	return loc
}

// TestOversizedParamsRejected caps every client-controlled value before
// anything is written: an anonymous caller could otherwise store ~1 MiB per
// request (H4).
func (s *AuthorizeSuite) TestOversizedParamsRejected() {
	long := func(n int) string { return strings.Repeat("a", n) }
	cases := []struct {
		name  string
		param string
		value string
	}{
		{"state over 512 bytes", "state", long(513)},
		{"nonce over 512 bytes", "nonce", long(513)},
		{"scope over 1 KiB", "scope", "openid " + long(1024)},
		{"client_id over 256 bytes", "client_id", long(257)},
		{"redirect_uri over 2 KiB", "redirect_uri", testRedirectURI + "?" + long(2048)},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			q := validParams()
			q.Set(tc.param, tc.value)
			resp := s.get(s.srv, q)
			defer resp.Body.Close()

			s.Equal(http.StatusBadRequest, resp.StatusCode)
			var body struct {
				Error string `json:"error"`
				Desc  string `json:"error_description"`
			}
			s.Require().NoError(json.NewDecoder(resp.Body).Decode(&body))
			s.Equal("invalid_request", body.Error)
			s.Contains(body.Desc, tc.param)
			s.Empty(resp.Header.Get("Location"))
			s.Zero(s.store.count(), "nothing is persisted")
		})
	}
}

func (s *AuthorizeSuite) TestParamsAtTheCapAreAccepted() {
	q := validParams()
	q.Set("state", strings.Repeat("s", 512))
	q.Set("nonce", strings.Repeat("n", 512))
	q.Set("scope", "openid "+strings.Repeat("x", 1024-len("openid ")))
	resp := s.get(s.srv, q)
	defer resp.Body.Close()

	s.Equal(http.StatusFound, resp.StatusCode)
	s.Equal(1, s.store.count())
}

func (s *AuthorizeSuite) TestStorePersistFailureIsServerError() {
	store := &memAuthStore{saveErr: errors.New("boom")}
	srv := s.serverFor(store,
		oidc.WithClock(func() time.Time { return fixedNow }),
		oidc.WithStateGenerator(func() (string, error) { return fixedState, nil }),
	)
	defer srv.Close()

	resp := s.get(srv, validParams())
	defer resp.Body.Close()

	s.Equal(http.StatusInternalServerError, resp.StatusCode)
	s.Zero(store.count())
}

func (s *AuthorizeSuite) TestDefaultStateGeneratorProducesOpaqueState() {
	store := &memAuthStore{}
	srv := s.serverFor(store) // no WithStateGenerator: exercises crypto/rand path
	defer srv.Close()

	resp := s.get(srv, validParams())
	defer resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)

	loc, err := url.Parse(resp.Header.Get("Location"))
	s.Require().NoError(err)
	state := loc.Query().Get("state")

	raw, err := base64.RawURLEncoding.DecodeString(state)
	s.Require().NoError(err)
	s.Len(raw, 32)
	s.Equal(state, store.only().InternalState)
}

func (s *AuthorizeSuite) TestMalformedGoogleEndpointIsServerError() {
	reg, err := oidc.ParseClientRegistry("ui:" + testRedirectURI)
	s.Require().NoError(err)
	a := oidc.New(&memAuthStore{}, reg, testIssuer, testGoogleCID, "http://%zz/bad")

	mux := http.NewServeMux()
	a.Register(humago.New(mux, huma.DefaultConfig("test", "0.0.0")))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp := s.get(srv, validParams())
	defer resp.Body.Close()
	s.Equal(http.StatusInternalServerError, resp.StatusCode)
}

func (s *AuthorizeSuite) TestStateGeneratorFailureIsServerError() {
	store := &memAuthStore{}
	srv := s.serverFor(store,
		oidc.WithStateGenerator(func() (string, error) {
			return "", errors.New("no entropy")
		}),
	)
	defer srv.Close()

	resp := s.get(srv, validParams())
	defer resp.Body.Close()

	s.Equal(http.StatusInternalServerError, resp.StatusCode)
	s.Zero(store.count())
}
