package oidc_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/stretchr/testify/suite"

	"github.com/onhotpath/tempogate/oidc"
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
	email    string
	verified bool
	err      error
	gotCode  string
}

func (f *fakeUpstream) ExchangeAndVerify(_ context.Context, code string) (string, bool, error) {
	f.gotCode = code
	if f.err != nil {
		return "", false, f.err
	}
	return f.email, f.verified, nil
}

type CallbackSuite struct {
	suite.Suite

	store  *memCallbackStore
	up     *fakeUpstream
	srv    *httptest.Server
	client *http.Client
}

func TestCallbackSuite(t *testing.T) {
	suite.Run(t, new(CallbackSuite))
}

func (s *CallbackSuite) SetupTest() {
	s.store = newMemCallbackStore()
	s.up = &fakeUpstream{email: "alice@example.com", verified: true}
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

func (s *CallbackSuite) serverFor(store oidc.CallbackStore, up oidc.Upstream) *httptest.Server {
	c := oidc.NewCallback(store, up, allowedDomains,
		oidc.WithCallbackClock(func() time.Time { return fixedNow }),
		oidc.WithCodeGenerator(func() (string, error) { return fixedCode, nil }),
	)
	mux := http.NewServeMux()
	c.Register(humago.New(mux, huma.DefaultConfig("test", "0.0.0")))
	return httptest.NewServer(mux)
}

func (s *CallbackSuite) pendingRequest(internalState string) oidc.AuthRequest {
	return oidc.AuthRequest{
		InternalState:       internalState,
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

func (s *CallbackSuite) get(q url.Values) *http.Response {
	resp, err := s.client.Get(s.srv.URL + "/callback/google?" + q.Encode())
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

	s.Require().Equal(1, s.store.codeCount())
	ac := s.store.only()
	s.Equal(fixedCode, ac.Code)
	s.Equal("ui", ac.ClientID)
	s.Equal(testRedirectURI, ac.RedirectURI)
	s.Equal("alice@example.com", ac.Email)
	s.Equal("openid email", ac.Scope)
	s.Equal("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", ac.CodeChallenge)
	s.Equal("S256", ac.CodeChallengeMethod)
	s.True(fixedNow.Equal(ac.CreatedAt))
	s.Equal(time.Minute, ac.ExpiresAt.Sub(ac.CreatedAt))
}

func (s *CallbackSuite) TestSubdomainCaseInsensitiveDomainMatch() {
	s.up.email = "BOB@corp.example.ORG"
	s.store.put(s.pendingRequest(fixedState))

	resp := s.get(callbackQuery("c", fixedState))
	defer resp.Body.Close()

	s.Equal(http.StatusFound, resp.StatusCode)
	s.Equal(1, s.store.codeCount())
}

func (s *CallbackSuite) TestEmailOutsideAllowedDomainsIsForbiddenPage() {
	s.up.email = "mallory@evil.example.net"
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

func (s *CallbackSuite) TestUnverifiedEmailIsForbiddenEvenIfDomainAllowed() {
	s.up.email = "alice@example.com"
	s.up.verified = false
	s.store.put(s.pendingRequest(fixedState))

	resp := s.get(callbackQuery("c", fixedState))
	defer resp.Body.Close()

	s.Equal(http.StatusForbidden, resp.StatusCode)
	s.Zero(s.store.codeCount())
}

func (s *CallbackSuite) TestForbiddenPageEscapesEmail() {
	s.up.email = `x"<script>@evil.net`
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
	c := oidc.NewCallback(store, &fakeUpstream{email: "alice@example.com", verified: true}, allowedDomains,
		oidc.WithCallbackClock(func() time.Time { return fixedNow }),
	) // no WithCodeGenerator: exercises crypto/rand path
	mux := http.NewServeMux()
	c.Register(humago.New(mux, huma.DefaultConfig("test", "0.0.0")))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := s.client.Get(srv.URL + "/callback/google?" + callbackQuery("c", fixedState).Encode())
	s.Require().NoError(err)
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
