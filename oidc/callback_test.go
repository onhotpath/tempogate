package oidc_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/onhotpath/tempogate/api"
	"github.com/onhotpath/tempogate/api/requestid"
	"github.com/onhotpath/tempogate/oidc"
	"github.com/onhotpath/tempogate/oidc/connector/google"
)

const (
	fixedCode      = "fixed-auth-code"
	allowedDomains = "example.com, Corp.Example.org"
)

// memCallbackStore satisfies oidc.CallbackStore structurally. ConsumeAuthRequest
// deletes the row so the single-use property is exercised by the suite, not
// just asserted in prose.
type memCallbackStore struct {
	mu         sync.Mutex
	requests   map[string]oidc.AuthRequest
	codes      []oidc.AuthCode
	consumeErr error
	saveErr    error
}

func newMemCallbackStore() *memCallbackStore {
	return &memCallbackStore{requests: map[string]oidc.AuthRequest{}}
}

func (m *memCallbackStore) put(ar oidc.AuthRequest) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests[ar.InternalState] = ar
}

func (m *memCallbackStore) pending(internalState string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.requests[internalState]
	return ok
}

// SaveAuthRequest lets one store back both /authorize and /callback/google
// in the round-trip tests.
func (m *memCallbackStore) SaveAuthRequest(_ context.Context, ar oidc.AuthRequest) error {
	m.put(ar)
	return nil
}

func (m *memCallbackStore) ConsumeAuthRequest(_ context.Context, internalState string) (oidc.AuthRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.consumeErr != nil {
		return oidc.AuthRequest{}, m.consumeErr
	}
	ar, ok := m.requests[internalState]
	if !ok {
		return oidc.AuthRequest{}, fmt.Errorf("%w: %s", oidc.ErrAuthRequestNotFound, internalState)
	}
	delete(m.requests, internalState)
	return ar, nil
}

func (m *memCallbackStore) SaveAuthCode(_ context.Context, ac oidc.AuthCode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.saveErr != nil {
		return m.saveErr
	}
	m.codes = append(m.codes, ac)
	return nil
}

func (m *memCallbackStore) only() oidc.AuthCode {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.codes[len(m.codes)-1]
}

func (m *memCallbackStore) codeCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.codes)
}

type fakeUpstream struct {
	id          google.Identity
	err         error
	gotCode     string
	gotRedirect string
	gotVerifier string
	gotNonce    string
}

func (f *fakeUpstream) ExchangeAndVerify(_ context.Context, code, redirectURI, codeVerifier, nonce string) (google.Identity, error) {
	f.gotCode = code
	f.gotRedirect = redirectURI
	f.gotVerifier = codeVerifier
	f.gotNonce = nonce
	if f.err != nil {
		return google.Identity{}, f.err
	}
	return f.id, nil
}

func aliceIdentity() google.Identity {
	return google.Identity{Subject: "google-sub-alice", Email: "alice@example.com", EmailVerified: true}
}

type CallbackSuite struct {
	suite.Suite

	store    *memCallbackStore
	up       *fakeUpstream
	binding  *oidc.UpstreamBinding
	logs     *bytes.Buffer
	srv      *httptest.Server
	client   *http.Client
	observed *recordingObserver
	resolver *stubResolver
}

func TestCallbackSuite(t *testing.T) {
	suite.Run(t, new(CallbackSuite))
}

func (s *CallbackSuite) SetupTest() {
	s.store = newMemCallbackStore()
	s.up = &fakeUpstream{id: aliceIdentity()}
	s.binding = newTestBinding(s.T(), testIssuer)
	s.logs = &bytes.Buffer{}
	s.observed = newRecordingObserver()
	s.resolver = newStubResolver("temporal-system:admin")
	s.srv = s.serverFor(s.store, s.up)
	s.client = &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (s *CallbackSuite) TearDownTest() {
	s.srv.Close()
}

func (s *CallbackSuite) serverFor(store oidc.CallbackStore, up google.Exchanger) *httptest.Server {
	c := oidc.NewCallback(store, googleConnectors(s.T(), up, ""), s.binding, allowedDomains, oidc.WithCallbackPermissionResolver(s.resolver),
		oidc.WithCallbackClock(func() time.Time { return fixedNow }),
		oidc.WithCodeGenerator(func() (string, error) { return fixedCode, nil }),
		oidc.WithCallbackIssuer(testIssuer),
		oidc.WithCallbackLogger(slog.New(slog.NewJSONHandler(s.logs, nil))),
		oidc.WithCallbackTelemetry(s.observed.Telemetry),
	)
	mux := http.NewServeMux()
	c.Register(humago.New(mux, huma.DefaultConfig("test", "0.0.0")))
	return httptest.NewServer(mux)
}

func (s *CallbackSuite) pendingRequest(internalState string) oidc.AuthRequest {
	return oidc.AuthRequest{
		InternalState:       internalState,
		ConnectorID:         "google",
		ClientID:            "ui",
		RedirectURI:         testRedirectURI,
		Scope:               "openid email",
		ClientState:         "client-state-abc",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		CreatedAt:           fixedNow,
		ExpiresAt:           fixedNow.Add(5 * time.Minute),
	}
}

// get plays the browser that started the flow: it presents the binding
// cookie /authorize set for the request's state.
func (s *CallbackSuite) get(q url.Values) *http.Response {
	return s.getFrom(s.srv, q, s.binding.Cookie("google", q.Get("state")))
}

func (s *CallbackSuite) getFrom(srv *httptest.Server, q url.Values, cookies ...*http.Cookie) *http.Response {
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/callback/google?"+q.Encode(), http.NoBody)
	s.Require().NoError(err)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := s.client.Do(req)
	s.Require().NoError(err)
	return resp
}

func callbackQuery(code, state string) url.Values {
	q := url.Values{}
	q.Set("code", code)
	q.Set("state", state)
	return q
}

func (s *CallbackSuite) decodeOAuthError(resp *http.Response) string {
	var body struct {
		Error string `json:"error"`
		Desc  string `json:"error_description"`
	}
	s.Require().NoError(json.NewDecoder(resp.Body).Decode(&body))
	s.NotEmpty(body.Desc)
	return body.Error
}

func (s *CallbackSuite) TestHappyPathRedirectsWithMintedCode() {
	s.store.put(s.pendingRequest(fixedState))

	resp := s.get(callbackQuery("google-code-xyz", fixedState))
	defer resp.Body.Close()

	s.Equal(http.StatusFound, resp.StatusCode)
	s.Equal("google-code-xyz", s.up.gotCode)

	loc, err := url.Parse(resp.Header.Get("Location"))
	s.Require().NoError(err)
	target, _ := url.Parse(testRedirectURI)
	s.Equal(target.Host, loc.Host)
	s.Equal(target.Path, loc.Path)
	s.Equal(fixedCode, loc.Query().Get("code"))
	s.Equal("client-state-abc", loc.Query().Get("state"))
	s.Equal(testIssuer, loc.Query().Get("iss"), "RFC 9207: every authorization response names its issuer")

	s.Require().Equal(1, s.store.codeCount())
	ac := s.store.only()
	s.Equal(fixedCode, ac.Code)
	s.Equal("ui", ac.ClientID)
	s.Equal(testRedirectURI, ac.RedirectURI)
	s.Equal("alice@example.com", ac.Email)
	s.Equal("google-sub-alice", ac.Subject, "the code carries Google's stable sub, not the email")
	s.Equal("google", ac.ConnectorID)
	s.Equal("openid email", ac.Scope)
	s.Equal("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", ac.CodeChallenge)
	s.Equal("S256", ac.CodeChallengeMethod)
	s.True(fixedNow.Equal(ac.CreatedAt))
	s.Equal(time.Minute, ac.ExpiresAt.Sub(ac.CreatedAt))
}

func (s *CallbackSuite) TestSubdomainCaseInsensitiveDomainMatch() {
	s.up.id.Email = "BOB@corp.example.ORG"
	s.store.put(s.pendingRequest(fixedState))

	resp := s.get(callbackQuery("c", fixedState))
	defer resp.Body.Close()

	s.Equal(http.StatusFound, resp.StatusCode)
	s.Equal(1, s.store.codeCount())
}

func (s *CallbackSuite) TestEmailOutsideAllowedDomainsIsForbiddenPage() {
	s.up.id.Email = "mallory@evil.example.net"
	s.store.put(s.pendingRequest(fixedState))

	resp := s.get(callbackQuery("c", fixedState))
	defer resp.Body.Close()

	s.Equal(http.StatusForbidden, resp.StatusCode)
	s.Equal("text/html; charset=utf-8", resp.Header.Get("Content-Type"))
	s.Empty(resp.Header.Get("Location"))

	body, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)
	s.Contains(string(body), "mallory@evil.example.net")
	s.Contains(string(body), "Access denied")

	s.Zero(s.store.codeCount())
}

// TestHostedDomainGate is the M5 acceptance: in Workspace mode
// (OIDC_ALLOWED_HOSTED_DOMAINS set) the upstream id_token's `hd` claim must
// be in that list, on top of email_verified and the email-suffix allowlist.
// A consumer Google account for an allowed address carries no `hd` and must
// not be admitted.
func (s *CallbackSuite) TestHostedDomainGate() {
	cases := []struct {
		name   string
		hosted string
		email  string
		hd     string
		admit  bool
	}{
		{name: "workspace off: no hd admitted (unchanged)", hosted: "", email: "alice@example.com", hd: "", admit: true},
		{name: "workspace off: foreign hd admitted (unchanged)", hosted: "", email: "alice@example.com", hd: "evil.test", admit: true},
		{name: "workspace on: missing hd rejected", hosted: "example.com", email: "alice@example.com", hd: "", admit: false},
		{name: "workspace on: foreign hd rejected", hosted: "example.com", email: "alice@example.com", hd: "evil.test", admit: false},
		{name: "workspace on: parent of hd is not a match", hosted: "example.com", email: "alice@example.com", hd: "sub.example.com", admit: false},
		{name: "workspace on: matching hd admitted", hosted: "example.com", email: "alice@example.com", hd: "example.com", admit: true},
		{name: "workspace on: hd match is case-insensitive", hosted: " Example.COM ", email: "alice@example.com", hd: "EXAMPLE.com", admit: true},
		{name: "workspace on: any listed hd admitted", hosted: "other.test, corp.example.org", email: "bob@corp.example.org", hd: "corp.example.org", admit: true},
		{name: "workspace on: matching hd does not bypass the email allowlist", hosted: "evil.test", email: "mallory@evil.test", hd: "evil.test", admit: false},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			store := newMemCallbackStore()
			store.put(s.pendingRequest(fixedState))
			up := &fakeUpstream{id: google.Identity{
				Subject: "google-sub-x", Email: tc.email, EmailVerified: true, HostedDomain: tc.hd,
			}}
			c := oidc.NewCallback(store, googleConnectors(s.T(), up, tc.hosted), s.binding, allowedDomains, oidc.WithCallbackPermissionResolver(permitAll),
				oidc.WithCallbackClock(func() time.Time { return fixedNow }),
				oidc.WithCodeGenerator(func() (string, error) { return fixedCode, nil }),
			)
			mux := http.NewServeMux()
			c.Register(humago.New(mux, huma.DefaultConfig("test", "0.0.0")))
			srv := httptest.NewServer(mux)
			defer srv.Close()

			resp := s.getFrom(srv, callbackQuery("c", fixedState), s.binding.Cookie("google", fixedState))
			defer resp.Body.Close()

			if tc.admit {
				s.Equal(http.StatusFound, resp.StatusCode)
				s.Equal(1, store.codeCount())
				return
			}
			s.Equal(http.StatusForbidden, resp.StatusCode)
			s.Empty(resp.Header.Get("Location"), "a rejected identity must not be redirected back with a code")
			s.Zero(store.codeCount(), "no authorization code may be minted for a rejected identity")
		})
	}
}

func (s *CallbackSuite) TestMissingSubjectIsBadGateway() {
	s.up.id.Subject = ""
	s.store.put(s.pendingRequest(fixedState))

	resp := s.get(callbackQuery("c", fixedState))
	defer resp.Body.Close()

	s.Equal(http.StatusBadGateway, resp.StatusCode)
	s.Zero(s.store.codeCount())
}

func (s *CallbackSuite) TestUnverifiedEmailIsForbiddenEvenIfDomainAllowed() {
	s.up.id.Email = "alice@example.com"
	s.up.id.EmailVerified = false
	s.store.put(s.pendingRequest(fixedState))

	resp := s.get(callbackQuery("c", fixedState))
	defer resp.Body.Close()

	s.Equal(http.StatusForbidden, resp.StatusCode)
	s.Zero(s.store.codeCount())
}

func (s *CallbackSuite) TestForbiddenPageEscapesEmail() {
	s.up.id.Email = `x"<script>@evil.net`
	s.store.put(s.pendingRequest(fixedState))

	resp := s.get(callbackQuery("c", fixedState))
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)
	s.NotContains(string(body), "<script>")
	s.Contains(string(body), "&lt;script&gt;")
}

func (s *CallbackSuite) TestStateMissingOrUnknownIsBadRequest() {
	cases := []struct {
		name  string
		state string
		seed  bool
	}{
		{"missing state", "", false},
		{"unknown state", "never-issued", false},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			resp := s.get(callbackQuery("c", tc.state))
			defer resp.Body.Close()

			s.Equal(http.StatusBadRequest, resp.StatusCode)
			s.Equal("invalid_request", s.decodeOAuthError(resp))
			s.Empty(resp.Header.Get("Location"))
			s.Zero(s.store.codeCount())
		})
	}
}

func (s *CallbackSuite) TestInternalStateIsSingleUse() {
	s.store.put(s.pendingRequest(fixedState))

	first := s.get(callbackQuery("c", fixedState))
	first.Body.Close()
	s.Require().Equal(http.StatusFound, first.StatusCode)

	second := s.get(callbackQuery("c", fixedState))
	defer second.Body.Close()
	s.Equal(http.StatusBadRequest, second.StatusCode)
	s.Equal("invalid_request", s.decodeOAuthError(second))
	s.Equal(1, s.store.codeCount())
}

func (s *CallbackSuite) TestExpiredAuthRequestIsBadRequest() {
	ar := s.pendingRequest(fixedState)
	ar.ExpiresAt = fixedNow.Add(-time.Second)
	s.store.put(ar)

	resp := s.get(callbackQuery("c", fixedState))
	defer resp.Body.Close()

	s.Equal(http.StatusBadRequest, resp.StatusCode)
	s.Equal("invalid_request", s.decodeOAuthError(resp))
	s.Zero(s.store.codeCount())
}

func (s *CallbackSuite) TestMissingCodeIsBadRequest() {
	s.store.put(s.pendingRequest(fixedState))

	q := url.Values{}
	q.Set("state", fixedState)
	resp := s.get(q)
	defer resp.Body.Close()

	s.Equal(http.StatusBadRequest, resp.StatusCode)
	s.Equal("invalid_request", s.decodeOAuthError(resp))
}

func (s *CallbackSuite) TestUpstreamFailureIsBadGateway() {
	s.up.err = errors.New("google said no")
	s.store.put(s.pendingRequest(fixedState))

	resp := s.get(callbackQuery("c", fixedState))
	defer resp.Body.Close()

	s.Equal(http.StatusBadGateway, resp.StatusCode)
	s.Equal("upstream_error", s.decodeOAuthError(resp))
	s.Zero(s.store.codeCount())
}

// TestUpstreamFailureKeepsOAuthShapeBehindSanitizer serves the callback
// through the real API surface: its 502 upstream_error is written for the
// client, so the 5xx sanitizer keeps the OAuth body (no upstream detail in
// it) and still logs the failure under the response's request id.
func (s *CallbackSuite) TestUpstreamFailureKeepsOAuthShapeBehindSanitizer() {
	s.up.err = errors.New("dial tcp 10.9.8.7:443: connection refused")
	s.store.put(s.pendingRequest(fixedState))
	c := oidc.NewCallback(s.store, googleConnectors(s.T(), s.up, ""), s.binding, allowedDomains, oidc.WithCallbackPermissionResolver(permitAll),
		oidc.WithCallbackClock(func() time.Time { return fixedNow }),
		oidc.WithCallbackIssuer(testIssuer),
		oidc.WithCallbackLogger(slog.New(slog.NewJSONHandler(io.Discard, nil))),
	)
	core, apiLogs := observer.New(zapcore.DebugLevel)
	srv := httptest.NewServer(api.New(api.NewReadiness(),
		api.WithLogger(zap.New(core)),
		api.WithRegistrar(c.Register),
	).Public.Handler)
	defer srv.Close()

	q := callbackQuery("c", fixedState)
	resp := s.getFrom(srv, q, s.binding.Cookie("google", q.Get("state")))
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)

	s.Equal(http.StatusBadGateway, resp.StatusCode)
	s.JSONEq(`{"error":"upstream_error","error_description":"could not complete Google sign-in"}`, string(raw))
	reqID := resp.Header.Get(requestid.Header)
	s.Require().NotEmpty(reqID)
	s.Len(apiLogs.FilterField(zap.String("request_id", reqID)).All(), 1)
}

func (s *CallbackSuite) TestGoogleErrorIsForwardedToClient() {
	s.store.put(s.pendingRequest(fixedState))

	q := url.Values{}
	q.Set("state", fixedState)
	q.Set("error", "access_denied")
	q.Set("error_description", "user refused consent")
	resp := s.get(q)
	defer resp.Body.Close()

	s.Equal(http.StatusFound, resp.StatusCode)
	loc, err := url.Parse(resp.Header.Get("Location"))
	s.Require().NoError(err)
	s.Equal("access_denied", loc.Query().Get("error"))
	s.Equal("user refused consent", loc.Query().Get("error_description"))
	s.Equal("client-state-abc", loc.Query().Get("state"))
	s.Equal(testIssuer, loc.Query().Get("iss"))
	s.Empty(loc.Query().Get("code"))
	s.Zero(s.store.codeCount())
}

func (s *CallbackSuite) TestSaveAuthCodeFailureIsServerError() {
	s.store.saveErr = errors.New("disk full")
	s.store.put(s.pendingRequest(fixedState))

	resp := s.get(callbackQuery("c", fixedState))
	defer resp.Body.Close()

	s.Equal(http.StatusInternalServerError, resp.StatusCode)
}

func (s *CallbackSuite) TestMalformedRedirectURIIsServerError() {
	ar := s.pendingRequest(fixedState)
	ar.RedirectURI = "http://%zz/bad"
	s.store.put(ar)

	resp := s.get(callbackQuery("c", fixedState))
	defer resp.Body.Close()

	s.Equal(http.StatusInternalServerError, resp.StatusCode)
}

func (s *CallbackSuite) TestDefaultCodeGeneratorIsOpaque() {
	store := newMemCallbackStore()
	store.put(s.pendingRequest(fixedState))
	c := oidc.NewCallback(store, googleConnectors(s.T(), &fakeUpstream{id: aliceIdentity()}, ""), s.binding, allowedDomains, oidc.WithCallbackPermissionResolver(permitAll),
		oidc.WithCallbackClock(func() time.Time { return fixedNow }),
	) // no WithCodeGenerator: exercises crypto/rand path
	mux := http.NewServeMux()
	c.Register(humago.New(mux, huma.DefaultConfig("test", "0.0.0")))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp := s.getFrom(srv, callbackQuery("c", fixedState), s.binding.Cookie("google", fixedState))
	defer resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)

	loc, err := url.Parse(resp.Header.Get("Location"))
	s.Require().NoError(err)
	raw, err := base64.RawURLEncoding.DecodeString(loc.Query().Get("code"))
	s.Require().NoError(err)
	s.Len(raw, 32)
	s.Equal(loc.Query().Get("code"), store.only().Code)
}

func (s *CallbackSuite) TestConsumeErrorOtherThanNotFoundIsServerError() {
	s.store.consumeErr = errors.New("db exploded")

	resp := s.get(callbackQuery("c", fixedState))
	defer resp.Body.Close()

	s.Equal(http.StatusInternalServerError, resp.StatusCode)
}

// TestStateNotBoundToBrowserIsRejected is the login-CSRF / code-injection
// regression: a valid internal state presented by a browser that did not
// start the flow (no binding cookie, a cookie for another state, or a forged
// value) is refused before the state is consumed or the code exchanged.
func (s *CallbackSuite) TestStateNotBoundToBrowserIsRejected() {
	tampered := s.binding.Cookie("google", fixedState)
	tampered.Value = s.binding.Cookie("google", "some-other-state").Value
	otherState := s.binding.Cookie("google", "some-other-state")
	otherState.Name = s.binding.Cookie("google", fixedState).Name

	cases := map[string][]*http.Cookie{
		"no binding cookie":          nil,
		"cookie for another state":   {s.binding.Cookie("google", "some-other-state")},
		"forged value":               {tampered},
		"another state's value":      {otherState},
		"cookie from another server": {newTestBindingWithKey(s.T(), testIssuer, "fedcba9876543210fedcba9876543210").Cookie("google", fixedState)},
	}
	for name, cookies := range cases {
		s.Run(name, func() {
			s.store.put(s.pendingRequest(fixedState))
			s.up.gotCode = ""

			resp := s.getFrom(s.srv, callbackQuery("attacker-code", fixedState), cookies...)
			defer resp.Body.Close()

			s.Equal(http.StatusBadRequest, resp.StatusCode)
			s.Equal("invalid_request", s.decodeOAuthError(resp))
			s.Empty(resp.Header.Get("Location"))
			s.Empty(s.up.gotCode, "the code must not be exchanged")
			s.Zero(s.store.codeCount())
			s.True(s.store.pending(fixedState), "an unbound request must not consume the state")
		})
	}
	s.Contains(s.logs.String(), `"cause":"state_not_bound_to_browser"`)
	s.NotContains(s.logs.String(), "attacker-code")
}

func (s *CallbackSuite) TestGoogleErrorRequiresBinding() {
	s.store.put(s.pendingRequest(fixedState))

	q := url.Values{}
	q.Set("state", fixedState)
	q.Set("error", "access_denied")
	resp := s.getFrom(s.srv, q)
	defer resp.Body.Close()

	s.Equal(http.StatusBadRequest, resp.StatusCode)
	s.Empty(resp.Header.Get("Location"))
}

func (s *CallbackSuite) TestUpstreamGetsTheRequestsVerifierAndNonce() {
	s.store.put(s.pendingRequest(fixedState))

	resp := s.get(callbackQuery("c", fixedState))
	defer resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)

	s.NotEmpty(s.up.gotVerifier)
	s.NotEmpty(s.up.gotNonce)
	s.GreaterOrEqual(len(s.up.gotVerifier), 43, "RFC 7636 verifier minimum length")
}

func (s *CallbackSuite) TestSuccessClearsBindingCookie() {
	s.store.put(s.pendingRequest(fixedState))

	resp := s.get(callbackQuery("c", fixedState))
	defer resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)

	want := s.binding.Cookie("google", fixedState)
	var cleared bool
	for _, c := range resp.Cookies() {
		if c.Name == want.Name && c.MaxAge < 0 {
			cleared = true
			s.Equal(want.Path, c.Path)
		}
	}
	s.True(cleared, "a completed login must drop its binding cookie")
}

// TestUpstreamFailureIsLoggedWithReason covers the operator trail for a
// failed Google sign-in: one warn line carrying the failure category, never
// the code or any token.
func (s *CallbackSuite) TestUpstreamFailureIsLoggedWithReason() {
	cases := []struct {
		name      string
		err       error
		cause     string
		oauthCode string
		timeout   bool
	}{
		{"nonce mismatch", &oidc.UpstreamError{Reason: oidc.UpstreamReasonNonce, Err: errors.New("nonce secret-nonce-value")}, oidc.UpstreamReasonNonce, "", false},
		{"exchange rejected", &oidc.UpstreamError{Reason: oidc.UpstreamReasonExchange, OAuthError: "invalid_grant", Err: errors.New("body with secret-token")}, oidc.UpstreamReasonExchange, "invalid_grant", false},
		{"wrapped", fmt.Errorf("outer: %w", &oidc.UpstreamError{Reason: oidc.UpstreamReasonDiscovery, Err: errors.New("dns")}), oidc.UpstreamReasonDiscovery, "", false},
		{"timed out", &oidc.UpstreamError{Reason: oidc.UpstreamReasonExchange, Timeout: true, Err: errors.New("deadline")}, oidc.UpstreamReasonExchange, "", true},
		{"unclassified", errors.New("secret-token in an unknown error"), "unknown", "", false},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			s.logs.Reset()
			s.up.err = tc.err
			s.store.put(s.pendingRequest(fixedState))

			resp := s.get(callbackQuery("google-code-secret", fixedState))
			defer resp.Body.Close()
			s.Require().Equal(http.StatusBadGateway, resp.StatusCode)

			var line map[string]any
			s.Require().NoError(json.Unmarshal(s.logs.Bytes(), &line), "exactly one JSON log line: %s", s.logs.String())
			s.Equal("WARN", line["level"])
			s.Equal(tc.cause, line["cause"])
			if tc.oauthCode != "" {
				s.Equal(tc.oauthCode, line["oauth_error"])
			}
			if tc.timeout {
				s.Equal(true, line["timeout"])
			} else {
				s.NotContains(line, "timeout")
			}
			for _, secret := range []string{"google-code-secret", "secret-token", "secret-nonce-value"} {
				s.NotContains(s.logs.String(), secret)
			}
		})
	}
}

func (s *CallbackSuite) TestMissingSubjectIsLogged() {
	s.up.id.Subject = ""
	s.store.put(s.pendingRequest(fixedState))

	resp := s.get(callbackQuery("c", fixedState))
	defer resp.Body.Close()

	s.Equal(http.StatusBadGateway, resp.StatusCode)
	s.Contains(s.logs.String(), `"cause":"`+oidc.UpstreamReasonClaims+`"`)
}

// s256 is the RFC 7636 S256 transform.
func TestUpstreamErrorUnwrapsToItsCause(t *testing.T) {
	cause := errors.New("token endpoint unreachable")
	err := &oidc.UpstreamError{Reason: oidc.UpstreamReasonExchange, Err: cause}
	if !errors.Is(err, cause) || err.Error() != cause.Error() {
		t.Fatalf("UpstreamError must wrap and describe its cause, got %v", err)
	}
}
