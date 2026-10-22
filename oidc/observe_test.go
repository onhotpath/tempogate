package oidc_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"

	"github.com/onhotpath/tempogate/oidc"
)

// recordingObserver satisfies oidc.LoginObserver, oidc.TokenObserver and
// oidc.RateLimitObserver and keeps every call so a test can assert the exact
// label values reported.
type recordingObserver struct {
	mu          sync.Mutex
	logins      []string
	tokens      []string
	revocations []string
	limited     []string
	authzDenied []string
}

func (r *recordingObserver) ObserveAuthzDenied(stage string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.authzDenied = append(r.authzDenied, stage)
}

func (r *recordingObserver) denials() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.authzDenied...)
}

func (r *recordingObserver) ObserveLogin(result, reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.logins = append(r.logins, result+"/"+reason)
}

func (r *recordingObserver) ObserveToken(grant, errorCode string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tokens = append(r.tokens, grant+"/"+errorCode)
}

func (r *recordingObserver) ObserveFamilyRevoked(event string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.revocations = append(r.revocations, event)
}

func (r *recordingObserver) ObserveRateLimited(endpoint string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.limited = append(r.limited, endpoint)
}

func (r *recordingObserver) loginCalls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.logins...)
}

func (r *recordingObserver) tokenCalls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.tokens...)
}

func (r *recordingObserver) revocationCalls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.revocations...)
}

func (r *recordingObserver) rateLimitCalls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.limited...)
}

func (s *CallbackSuite) TestLoginOutcomesAreObserved() {
	cases := []struct {
		name  string
		setup func()
		get   func() *http.Response
		want  string
	}{
		{"success", func() { s.store.put(s.pendingRequest(fixedState)) },
			func() *http.Response { return s.get(callbackQuery("google-code", fixedState)) }, "success/none"},
		{"missing state", func() {},
			func() *http.Response { return s.get(callbackQuery("google-code", "")) }, "failure/missing_state"},
		{"state not bound to this browser", func() { s.store.put(s.pendingRequest(fixedState)) },
			func() *http.Response { return s.getFrom(s.srv, callbackQuery("google-code", fixedState)) }, "failure/state_not_bound"},
		{"unknown state", func() {},
			func() *http.Response { return s.get(callbackQuery("google-code", "nope")) }, "failure/unknown_state"},
		{"expired request", func() {
			ar := s.pendingRequest(fixedState)
			ar.ExpiresAt = fixedNow.Add(-time.Second)
			s.store.put(ar)
		}, func() *http.Response { return s.get(callbackQuery("google-code", fixedState)) }, "failure/expired_request"},
		{"upstream denied", func() { s.store.put(s.pendingRequest(fixedState)) },
			func() *http.Response {
				return s.get(url.Values{"state": {fixedState}, "error": {"access_denied"}})
			}, "failure/upstream_denied"},
		{"missing code", func() { s.store.put(s.pendingRequest(fixedState)) },
			func() *http.Response { return s.get(callbackQuery("", fixedState)) }, "failure/missing_code"},
		{"upstream error", func() {
			s.store.put(s.pendingRequest(fixedState))
			s.up.err = errors.New("google down")
		}, func() *http.Response { return s.get(callbackQuery("google-code", fixedState)) }, "failure/upstream_error"},
		{"email unverified", func() {
			s.store.put(s.pendingRequest(fixedState))
			s.up.id.EmailVerified = false
		}, func() *http.Response { return s.get(callbackQuery("google-code", fixedState)) }, "failure/email_unverified"},
		{"domain not allowed", func() {
			s.store.put(s.pendingRequest(fixedState))
			s.up.id.Email = "mallory@evil.example"
		}, func() *http.Response { return s.get(callbackQuery("google-code", fixedState)) }, "failure/domain_not_allowed"},
		{"store failure", func() { s.store.consumeErr = errors.New("db exploded") },
			func() *http.Response { return s.get(callbackQuery("google-code", fixedState)) }, "failure/internal"},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			// Fresh store, upstream and observer per case; the suite's own
			// TearDownTest closes whichever server is current at the end.
			s.TearDownTest()
			s.SetupTest()
			tc.setup()

			resp := tc.get()
			_ = resp.Body.Close()

			s.Equal([]string{tc.want}, s.observed.loginCalls())
		})
	}
}

// Workspace mode refuses an identity whose hd claim is not listed, under its
// own reason so a misconfigured OIDC_ALLOWED_HOSTED_DOMAINS is visible.
func (s *CallbackSuite) TestHostedDomainRefusalIsObserved() {
	s.store.put(s.pendingRequest(fixedState))
	c := oidc.NewCallback(s.store, googleConnectors(s.T(), s.up, "example.com"), s.binding, allowedDomains, oidc.WithCallbackPermissionResolver(permitAll),
		oidc.WithCallbackClock(func() time.Time { return fixedNow }),
		oidc.WithLoginObserver(s.observed),
	)
	mux := http.NewServeMux()
	c.Register(humago.New(mux, huma.DefaultConfig("test", "0.0.0")))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp := s.getFrom(srv, callbackQuery("c", fixedState), s.binding.Cookie("google", fixedState))
	_ = resp.Body.Close()

	s.Equal(http.StatusForbidden, resp.StatusCode)
	s.Equal([]string{"failure/hosted_domain_not_allowed"}, s.observed.loginCalls())
}

// A failure to mint our own authorization code after Google admitted the
// user is an internal failure, not a refusal: no code reaches the client.
func (s *CallbackSuite) TestCodeGenerationFailureIsObserved() {
	s.store.put(s.pendingRequest(fixedState))
	c := oidc.NewCallback(s.store, googleConnectors(s.T(), s.up, ""), s.binding, allowedDomains, oidc.WithCallbackPermissionResolver(permitAll),
		oidc.WithCallbackClock(func() time.Time { return fixedNow }),
		oidc.WithCodeGenerator(func() (string, error) { return "", errors.New("entropy exhausted") }),
		oidc.WithLoginObserver(s.observed),
	)
	mux := http.NewServeMux()
	c.Register(humago.New(mux, huma.DefaultConfig("test", "0.0.0")))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp := s.getFrom(srv, callbackQuery("c", fixedState), s.binding.Cookie("google", fixedState))
	_ = resp.Body.Close()

	s.Equal(http.StatusInternalServerError, resp.StatusCode)
	s.Empty(resp.Header.Get("Location"))
	s.Equal([]string{"failure/internal"}, s.observed.loginCalls())
}

func (s *TokenSuite) TestTokenOutcomesAreObservedPerGrant() {
	// authorization_code: minted.
	s.store.putCode(s.authCode("code-1"))
	resp := s.post(authCodeForm())
	_ = resp.Body.Close()

	// refresh_token: minted.
	s.seedRefresh("rt-1", "ui")
	refresh := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"rt-1"}, "client_id": {"ui"}}
	resp = s.post(refresh)
	_ = resp.Body.Close()

	// device_code: pending, then approved and minted.
	s.seedPending("dc-1", "BCDFGHJK")
	resp = s.post(deviceForm("dc-1", "tempogate-device"))
	_ = resp.Body.Close()
	s.seedPending("dc-2", "CDFGHJKL")
	s.approve("CDFGHJKL", aliceID())
	resp = s.post(deviceForm("dc-2", "tempogate-device"))
	_ = resp.Body.Close()

	// Errors carry the OAuth2 code, never the raw grant_type.
	resp = s.post(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"never-issued"}, "client_id": {"ui"}})
	_ = resp.Body.Close()
	resp = s.post(url.Values{"grant_type": {"password"}, "username": {"alice"}})
	_ = resp.Body.Close()
	resp = s.post(url.Values{"filler": {"x"}})
	_ = resp.Body.Close()

	s.Equal([]string{
		"authorization_code/",
		"refresh_token/",
		"device_code/authorization_pending",
		"device_code/",
		"refresh_token/invalid_grant",
		"other/unsupported_grant_type",
		"other/invalid_request",
	}, s.observed.tokenCalls())
	s.Empty(s.observed.revocationCalls())
}

// A confidential client presenting the wrong secret is counted under
// invalid_client, which is how a leaked or rotated secret shows up.
func (s *TokenSuite) TestClientAuthFailureIsObserved() {
	s.seedRefresh("rt-conf", "webui")
	f := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"rt-conf"}, "client_id": {"webui"}, "client_secret": {"wrong"}}
	resp := s.post(f)
	_ = resp.Body.Close()

	s.Equal([]string{"refresh_token/invalid_client"}, s.observed.tokenCalls())
}

// Every family tempogate revokes on its own is counted by the security event
// that triggered it.
func (s *TokenSuite) TestFamilyRevocationsAreObserved() {
	// A replayed authorization code.
	s.store.putCode(s.authCode("code-1"))
	for range 2 {
		resp := s.post(authCodeForm())
		_ = resp.Body.Close()
	}

	// A replayed refresh token.
	s.seedRefresh("rt-1", "ui")
	refresh := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"rt-1"}, "client_id": {"ui"}}
	for range 2 {
		resp := s.post(refresh)
		_ = resp.Body.Close()
	}

	// A refresh for a domain that is no longer allowed.
	s.store.putRefresh(oidc.Refresh{
		Token: "rt-evil", JTI: "jti-evil", ClientID: "ui", ConnectorID: "google", Subject: "google-sub-mallory", Email: "mallory@evil.example",
		FamilyID: "family-evil", AuthTime: signNow, CreatedAt: signNow, ExpiresAt: signNow.Add(time.Hour),
	})
	resp := s.post(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"rt-evil"}, "client_id": {"ui"}})
	_ = resp.Body.Close()

	s.Equal([]string{"auth_code_reuse", "refresh_token_reuse", "refresh_domain_not_allowed"}, s.observed.revocationCalls())
	s.Equal([]string{
		"authorization_code/",
		"authorization_code/invalid_grant",
		"refresh_token/",
		"refresh_token/invalid_grant",
		"refresh_token/invalid_grant",
	}, s.observed.tokenCalls())
}

func (s *TokenSuite) TestTokenServerErrorIsObserved() {
	s.store.consumeCodeErr = errors.New("db exploded")

	resp := s.post(authCodeForm())
	_ = resp.Body.Close()

	s.Equal([]string{"authorization_code/server_error"}, s.observed.tokenCalls())
}
