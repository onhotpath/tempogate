package oidc_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/stretchr/testify/require"

	"github.com/onhotpath/tempogate/oidc"
	"github.com/onhotpath/tempogate/oidc/connector/google"
)

// googleConnector is the real Google connector in front of up, so the
// server's callback tests exercise Google's gates without a network.
func googleConnector(t testing.TB, up google.Exchanger, hostedDomains string) oidc.Connector {
	t.Helper()
	conn, err := google.NewConnector(google.Config{
		ClientID:      testGoogleCID,
		AuthEndpoint:  testGoogleAuth,
		IssuerURL:     "https://accounts.google.com",
		HostedDomains: hostedDomains,
	}, up)
	require.NoError(t, err)
	return conn
}

func googleConnectors(t testing.TB, up google.Exchanger, hostedDomains string) *oidc.Connectors {
	t.Helper()
	return connectorsOf(t, googleConnector(t, up, hostedDomains))
}

// googleConnectorsAt points the Google connector at a mock IdP's issuer.
func googleConnectorsAt(t testing.TB, issuer string, up google.Exchanger, hostedDomains string) *oidc.Connectors {
	t.Helper()
	conn, err := google.NewConnector(google.Config{
		ClientID:      testGoogleCID,
		AuthEndpoint:  issuer + "/auth",
		IssuerURL:     issuer,
		HostedDomains: hostedDomains,
	}, up)
	require.NoError(t, err)
	return connectorsOf(t, conn)
}

func connectorsOf(t testing.TB, cs ...oidc.Connector) *oidc.Connectors {
	t.Helper()
	conns, err := oidc.NewConnectors(cs...)
	require.NoError(t, err)
	return conns
}

// fakeConnector is a second, non-Google connector: it records what the
// server hands it and answers with whatever the test sets.
type fakeConnector struct {
	id   string
	flow oidc.Flow

	beginErr   error
	completion oidc.Completion
	err        error
	// block makes Complete wait for its context, like a stalled upstream.
	block bool

	mu        sync.Mutex
	began     []oidc.BeginParams
	completed []oidc.CompleteParams
}

func newFakeConnector(id string) *fakeConnector {
	return &fakeConnector{
		id:         id,
		flow:       oidc.Flow{ResponseMethod: http.MethodGet, StateParam: "state"},
		completion: oidc.Completion{Identity: oidc.UpstreamIdentity{Subject: "okta-sub-alice", Email: "alice@example.com", EmailVerified: true}},
	}
}

func (f *fakeConnector) ID() string          { return f.id }
func (f *fakeConnector) DisplayName() string { return "Okta" }
func (f *fakeConnector) Flow() oidc.Flow     { return f.flow }

func (f *fakeConnector) Begin(_ context.Context, p oidc.BeginParams) (oidc.Start, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.began = append(f.began, p)
	if f.beginErr != nil {
		return oidc.Start{}, f.beginErr
	}
	return oidc.Start{RedirectURL: "https://okta.example.com/authorize?state=" + url.QueryEscape(p.State)}, nil
}

func (f *fakeConnector) Complete(ctx context.Context, p oidc.CompleteParams) (oidc.Completion, error) {
	f.mu.Lock()
	f.completed = append(f.completed, p)
	f.mu.Unlock()
	if f.block {
		<-ctx.Done()
		return oidc.Completion{}, ctx.Err()
	}
	return f.completion, f.err
}

func (f *fakeConnector) FormActionSources(context.Context) ([]string, error) {
	return []string{"https://okta.example.com"}, nil
}

func (f *fakeConnector) completeCalls() []oidc.CompleteParams {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]oidc.CompleteParams(nil), f.completed...)
}

func TestValidateConnectorID(t *testing.T) {
	for _, id := range []string{"google", "okta", "a", "github2", strings.Repeat("a", 32)} {
		require.NoError(t, oidc.ValidateConnectorID(id), id)
	}
	for _, id := range []string{"", "Google", "2fa", "go-ogle", "go_ogle", "go:ogle", strings.Repeat("a", 33), "key", "tempogate", "system", "local"} {
		require.Error(t, oidc.ValidateConnectorID(id), id)
	}
}

func TestNewConnectors(t *testing.T) {
	okta := newFakeConnector("okta")
	conns, err := oidc.NewConnectors(okta)
	require.NoError(t, err)
	require.Same(t, okta, conns.Active())
	got, ok := conns.Lookup("okta")
	require.True(t, ok)
	require.Same(t, okta, got)
	_, ok = conns.Lookup("google")
	require.False(t, ok)

	post := newFakeConnector("saml")
	post.flow.ResponseMethod = http.MethodPost
	noState := newFakeConnector("okta")
	noState.flow.StateParam = ""
	for name, cs := range map[string][]oidc.Connector{
		"none":             nil,
		"two":              {newFakeConnector("okta"), newFakeConnector("github")},
		"reserved id":      {newFakeConnector("key")},
		"malformed id":     {newFakeConnector("Okta")},
		"POST response":    {post},
		"no state carrier": {noState},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := oidc.NewConnectors(cs...)
			require.Error(t, err)
		})
	}
}

// serveConnector mounts the callback for conns on the suite's store,
// binding, logs and observer.
func (s *CallbackSuite) serveConnector(conns *oidc.Connectors, opts ...oidc.CallbackOption) *httptest.Server {
	c := oidc.NewCallback(s.store, conns, s.binding, allowedDomains, append([]oidc.CallbackOption{
		oidc.WithCallbackPermissionResolver(permitAll),
		oidc.WithCallbackClock(func() time.Time { return fixedNow }),
		oidc.WithCodeGenerator(func() (string, error) { return fixedCode, nil }),
		oidc.WithCallbackIssuer(testIssuer),
		oidc.WithCallbackLogger(slog.New(slog.NewJSONHandler(s.logs, nil))),
		oidc.WithLoginObserver(s.observed),
	}, opts...)...)
	mux := http.NewServeMux()
	c.Register(humago.New(mux, huma.DefaultConfig("test", "0.0.0")))
	srv := httptest.NewServer(mux)
	s.T().Cleanup(srv.Close)
	return srv
}

func (s *CallbackSuite) callbackAt(srv *httptest.Server, connectorID string, q url.Values, cookies ...*http.Cookie) *http.Response {
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/callback/"+connectorID+"?"+q.Encode(), http.NoBody)
	s.Require().NoError(err)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := s.client.Do(req)
	s.Require().NoError(err)
	return resp
}

func (s *CallbackSuite) pendingFor(connectorID string) {
	ar := s.pendingRequest(fixedState)
	ar.ConnectorID = connectorID
	s.store.put(ar)
}

// TestOtherConnectorsStateIsNotBound: a state minted (and bound) for
// connector A, replayed at connector B's callback, fails the binding check,
// so B's upstream is never called and the state survives.
func (s *CallbackSuite) TestOtherConnectorsStateIsNotBound() {
	okta := newFakeConnector("okta")
	srv := s.serveConnector(connectorsOf(s.T(), okta))
	s.pendingFor("google")

	resp := s.callbackAt(srv, "okta", callbackQuery("c", fixedState), s.binding.Cookie("google", fixedState))
	defer resp.Body.Close()

	s.Equal(http.StatusBadRequest, resp.StatusCode)
	s.Equal("invalid_request", s.decodeOAuthError(resp))
	s.Empty(okta.completeCalls(), "the other connector's Complete must never run")
	s.True(s.store.pending(fixedState))
	s.Equal([]string{"failure/state_not_bound"}, s.observed.loginCalls())
	s.Contains(s.logs.String(), `"connector":"okta"`)
}

// TestConnectorMismatchIsRefused is the defence in depth behind the
// binding: a request stored for another connector is refused once consumed,
// even with a valid binding for this one.
func (s *CallbackSuite) TestConnectorMismatchIsRefused() {
	okta := newFakeConnector("okta")
	srv := s.serveConnector(connectorsOf(s.T(), okta))
	s.pendingFor("google")

	resp := s.callbackAt(srv, "okta", callbackQuery("c", fixedState), s.binding.Cookie("okta", fixedState))
	defer resp.Body.Close()

	s.Equal(http.StatusBadRequest, resp.StatusCode)
	s.Equal("invalid_request", s.decodeOAuthError(resp))
	s.Empty(okta.completeCalls())
	s.Zero(s.store.codeCount())
	s.Equal([]string{"failure/connector_mismatch"}, s.observed.loginCalls())
}

func (s *CallbackSuite) TestUnknownConnectorIsNotFound() {
	s.store.put(s.pendingRequest(fixedState))

	resp := s.callbackAt(s.srv, "okta", callbackQuery("c", fixedState), s.binding.Cookie("okta", fixedState))
	defer resp.Body.Close()

	s.Equal(http.StatusNotFound, resp.StatusCode)
	s.Empty(s.up.gotCode)
	s.True(s.store.pending(fixedState))
	s.Empty(s.observed.loginCalls(), "an unknown route is not a sign-in")
}

func (s *CallbackSuite) TestWrongMethodIsNotAllowed() {
	s.store.put(s.pendingRequest(fixedState))

	resp, err := s.client.PostForm(s.srv.URL+"/callback/google", callbackQuery("c", fixedState))
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Equal(http.StatusMethodNotAllowed, resp.StatusCode)
	s.Empty(s.up.gotCode)
	s.True(s.store.pending(fixedState))
	s.Empty(s.observed.loginCalls())
}

// TestCompleteOverBudgetIsBadGateway: a connector whose upstream stalls is
// cut off by the overall deadline, and the user gets the 502 instead of the
// server's write timeout resetting the connection.
func (s *CallbackSuite) TestCompleteOverBudgetIsBadGateway() {
	okta := newFakeConnector("okta")
	okta.block = true
	srv := s.serveConnector(connectorsOf(s.T(), okta), oidc.WithCompleteTimeout(20*time.Millisecond))
	s.pendingFor("okta")

	start := time.Now()
	resp := s.callbackAt(srv, "okta", callbackQuery("c", fixedState), s.binding.Cookie("okta", fixedState))
	defer resp.Body.Close()

	s.Less(time.Since(start), 5*time.Second)
	s.Equal(http.StatusBadGateway, resp.StatusCode)
	s.Equal("upstream_error", s.decodeOAuthError(resp))
	var line map[string]any
	s.Require().NoError(json.Unmarshal(s.logs.Bytes(), &line), s.logs.String())
	s.Equal("unknown", line["cause"])
	s.Equal(true, line["timeout"])
	s.Equal("okta", line["connector"])
	s.Equal([]string{"failure/upstream_error"}, s.observed.loginCalls())
}

// TestUpstreamErrorOverBudgetIsMarkedTimeout: a connector that reports its
// own reason for a call cut short by the overall deadline keeps the reason,
// and the log still says it timed out.
func (s *CallbackSuite) TestUpstreamErrorOverBudgetIsMarkedTimeout() {
	okta := newFakeConnector("okta")
	okta.err = &oidc.UpstreamError{Reason: oidc.UpstreamReasonExchange, Err: errors.New("context deadline exceeded")}
	okta.completion = oidc.Completion{}
	srv := s.serveConnector(connectorsOf(s.T(), okta), oidc.WithCompleteTimeout(-time.Second))
	s.pendingFor("okta")

	resp := s.callbackAt(srv, "okta", callbackQuery("c", fixedState), s.binding.Cookie("okta", fixedState))
	defer resp.Body.Close()

	s.Equal(http.StatusBadGateway, resp.StatusCode)
	var line map[string]any
	s.Require().NoError(json.Unmarshal(s.logs.Bytes(), &line), s.logs.String())
	s.Equal(oidc.UpstreamReasonExchange, line["cause"])
	s.Equal(true, line["timeout"])
}

// TestConnectorGetsTheBindingValuesBeginSent drives /authorize and the
// callback for a non-Google connector: Begin gets this connector's redirect
// URI and binding values, and Complete gets the matching verifier, nonce and
// request id for the same state.
func (s *CallbackSuite) TestConnectorGetsTheBindingValuesBeginSent() {
	okta := newFakeConnector("okta")
	conns := connectorsOf(s.T(), okta)
	reg, err := oidc.ParseClientRegistry("ui:" + testRedirectURI)
	s.Require().NoError(err)
	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("test", "0.0.0"))
	oidc.New(s.store, reg, s.binding, conns, testIssuer).Register(api)
	oidc.NewCallback(s.store, conns, s.binding, allowedDomains,
		oidc.WithCallbackPermissionResolver(permitAll),
		oidc.WithCallbackIssuer(testIssuer),
		oidc.WithCodeGenerator(func() (string, error) { return fixedCode, nil }),
	).Register(api)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := s.client.Get(srv.URL + "/authorize?" + validParams().Encode())
	s.Require().NoError(err)
	_ = resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)
	s.Require().True(strings.HasPrefix(resp.Header.Get("Location"), "https://okta.example.com/authorize?"))
	s.Require().Len(okta.began, 1)
	begin := okta.began[0]
	s.Equal(testIssuer+"/callback/okta", begin.RedirectURI)
	s.Regexp(`^_[0-9a-f]{64}$`, begin.RequestID, "a request id is an XML NCName")

	cookie := resp.Cookies()[0]
	resp = s.callbackAt(srv, "okta", callbackQuery("okta-code", begin.State), cookie)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)

	calls := okta.completeCalls()
	s.Require().Len(calls, 1)
	sum := sha256.Sum256([]byte(calls[0].CodeVerifier))
	s.Equal(begin.CodeChallenge, base64.RawURLEncoding.EncodeToString(sum[:]))
	s.Equal(begin.Nonce, calls[0].Nonce)
	s.Equal(begin.RequestID, calls[0].RequestID)
	s.Equal(begin.RedirectURI, calls[0].RedirectURI)
	s.Equal("okta-code", calls[0].Params.Get("code"))
	s.Equal("okta-sub-alice", s.store.only().Subject)
	s.Equal("okta", s.store.only().ConnectorID, "the code carries the connector the user signed in through")

	googleBinding := s.binding.Cookie("google", begin.State)
	s.Equal(cookie.Name, googleBinding.Name)
	s.NotEqual(cookie.Value, googleBinding.Value, "the binding is derived per connector")
}

// TestConnectorRefusalAndMissingResponse: the server maps a connector's own
// refusal to a 403 under its reason, after the shared gates, and a response
// without a code or assertion to 400.
func (s *CallbackSuite) TestConnectorRefusalAndMissingResponse() {
	cases := []struct {
		name   string
		set    func(*fakeConnector)
		status int
		reason string
	}{
		{"refusal", func(f *fakeConnector) { f.completion.Refusal = oidc.RefusalHostedDomainNotAllowed }, http.StatusForbidden, "hosted_domain_not_allowed"},
		{"shared gate first", func(f *fakeConnector) {
			f.completion.Refusal = oidc.RefusalHostedDomainNotAllowed
			f.completion.Identity.EmailVerified = false
		}, http.StatusForbidden, "email_unverified"},
		{"missing response", func(f *fakeConnector) { f.err = oidc.ErrMissingResponse }, http.StatusBadRequest, "missing_code"},
		{"denied", func(f *fakeConnector) { f.err = &oidc.UpstreamDenied{Code: "access_denied"} }, http.StatusFound, "upstream_denied"},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			s.observed = &recordingObserver{}
			okta := newFakeConnector("okta")
			tc.set(okta)
			srv := s.serveConnector(connectorsOf(s.T(), okta))
			s.pendingFor("okta")

			resp := s.callbackAt(srv, "okta", callbackQuery("c", fixedState), s.binding.Cookie("okta", fixedState))
			defer resp.Body.Close()

			s.Equal(tc.status, resp.StatusCode)
			s.Zero(s.store.codeCount())
			s.Equal([]string{"failure/" + tc.reason}, s.observed.loginCalls())
		})
	}
}

func TestUpstreamDeniedNamesTheCode(t *testing.T) {
	err := &oidc.UpstreamDenied{Code: "access_denied", Description: "user refused consent"}
	require.Contains(t, err.Error(), "access_denied")
	require.NotContains(t, err.Error(), "user refused consent")
}

// TestBindingIsScopedPerConnector: on plain http the cookie is scoped to the
// connector's own callback path, and every value differs per connector.
func TestBindingIsScopedPerConnector(t *testing.T) {
	b := newTestBinding(t, "http://localhost:8000/idp")
	require.Equal(t, "/idp/callback/okta", b.Cookie("okta", "st").Path)
	require.Equal(t, "/idp/callback/google", b.Cookie("google", "st").Path)
	require.NotEqual(t, b.Cookie("okta", "st").Value, b.Cookie("google", "st").Value)
	_, err := hex.DecodeString(strings.TrimPrefix(b.Cookie("okta", "st").Name, "tempogate_upstream_"))
	require.NoError(t, err, "the cookie name depends on the state only")
}

func TestTokenSubject(t *testing.T) {
	require.Equal(t, "google:1234", oidc.TokenSubject("google", "1234"))
	for sub, want := range map[string][2]string{
		"google:1234":     {"google", "1234"},
		"okta:00u1:extra": {"okta", "00u1:extra"},
	} {
		id, subject, err := oidc.ParseTokenSubject(sub)
		require.NoError(t, err, sub)
		require.Equal(t, want, [2]string{id, subject}, sub)
		require.Equal(t, sub, oidc.TokenSubject(id, subject), "round trip")
	}
	for _, sub := range []string{"", "1234", "google:", ":1234", "Google:1234", "key:1234"} {
		_, _, err := oidc.ParseTokenSubject(sub)
		require.Error(t, err, sub)
	}
}
