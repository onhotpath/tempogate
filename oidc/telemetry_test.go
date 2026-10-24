package oidc_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/onhotpath/tempogate/observe"
	"github.com/onhotpath/tempogate/observe/observetest"
	"github.com/onhotpath/tempogate/oidc"
)

// recordingObserver is an *oidc.Telemetry over an in-memory meter, read back
// as the exact label values each metric recorded.
type recordingObserver struct {
	*oidc.Telemetry
	meter *observetest.Meter
}

func newRecordingObserver() *recordingObserver {
	m := observetest.NewMeter()
	t, err := oidc.NewTelemetry(m, nil)
	if err != nil {
		panic(err)
	}
	return &recordingObserver{Telemetry: t, meter: m}
}

// labels joins the values of keys with "/" for every measurement on names,
// in order; a key a measurement lacks reads as empty.
func (r *recordingObserver) labels(names []string, keys ...string) []string {
	var out []string
	for _, m := range r.meter.Measurements(names...) {
		vals := make([]string, len(keys))
		for i, k := range keys {
			vals[i] = m.Attrs[k]
		}
		out = append(out, strings.Join(vals, "/"))
	}
	return out
}

func (r *recordingObserver) denials() []string {
	return r.labels([]string{"tempogate.authz_denied"}, "stage")
}

func (r *recordingObserver) loginCalls() []string {
	return r.labels([]string{"tempogate.logins"}, "result", "reason")
}

// tokenCalls reads a minted token as "grant/" and a failure as
// "grant/error".
func (r *recordingObserver) tokenCalls() []string {
	return r.labels([]string{"tempogate.tokens_issued", "tempogate.token_errors"}, "grant", "error")
}

func (r *recordingObserver) revocationCalls() []string {
	return r.labels([]string{"tempogate.refresh_family_revocations"}, "event")
}

func (r *recordingObserver) rateLimitCalls() []string {
	return r.labels([]string{"tempogate.rate_limited"}, "endpoint")
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
		oidc.WithCallbackTelemetry(s.observed.Telemetry),
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
		oidc.WithCallbackTelemetry(s.observed.Telemetry),
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

// Every instrument keeps the name, unit and buckets the exposition has
// always had (docs/operations.md).
func TestTelemetryDeclaresItsInstruments(t *testing.T) {
	m := observetest.NewMeter()
	_, err := oidc.NewTelemetry(m, nil)
	require.NoError(t, err)

	for _, name := range []string{
		"tempogate.logins", "tempogate.tokens_issued", "tempogate.token_errors",
		"tempogate.refresh_family_revocations", "tempogate.authz_denied",
		"tempogate.rate_limited", "tempogate.upstream_errors",
	} {
		cfg, ok := m.Declared(name)
		require.True(t, ok, name)
		assert.NotEmpty(t, cfg.Description, name)
	}
	cfg, ok := m.Declared("tempogate.upstream_request.duration")
	require.True(t, ok)
	assert.Equal(t, "s", cfg.Unit)
	assert.Equal(t, []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10}, cfg.Buckets)
}

func TestTelemetryDeclarationFailureIsReturned(t *testing.T) {
	boom := errors.New("boom")
	_, err := oidc.NewTelemetry(observetest.FailingMeter(boom), nil)
	require.ErrorIs(t, err, boom)
}

// A call the connector flagged as timed out is counted apart from one the
// upstream answered with an error, so a stalled IdP is visible as such.
func TestUpstreamTimeoutsCountedApart(t *testing.T) {
	obs := newRecordingObserver()
	ctx := context.Background()
	end(obs.StartUpstream(ctx, "discovery"))(&oidc.UpstreamError{Reason: oidc.UpstreamReasonDiscovery, Timeout: true, Err: errors.New("deadline")})
	end(obs.StartUpstream(ctx, "discovery"))(&oidc.UpstreamError{Reason: oidc.UpstreamReasonDiscovery, Err: errors.New("503")})
	end(obs.StartUpstream(ctx, "code_exchange"))(errors.New("not an UpstreamError"))
	end(obs.StartUpstream(ctx, "verify_id_token"))(nil)

	assert.Equal(t, []string{"discovery/timeout", "discovery/error", "code_exchange/error"},
		obs.labels([]string{"tempogate.upstream_errors"}, "op", "reason"))
	assert.Equal(t, []string{"discovery", "discovery", "code_exchange", "verify_id_token"},
		obs.labels([]string{"tempogate.upstream_request.duration"}, "op"), "failed calls are timed too")
}

// end is the func half of StartUpstream.
func end(_ context.Context, done func(error)) func(error) { return done }

// Inside a traced request an upstream call is a client span, failed with its
// reason and the error's message; outside one it is timed but not traced.
func TestUpstreamCallIsAClientSpan(t *testing.T) {
	tr := observetest.NewTracer()
	tm, err := oidc.NewTelemetry(nil, tr)
	require.NoError(t, err)

	ctx, root := tr.Start(context.Background(), "request", observe.AsRoot())
	callCtx, done := tm.StartUpstream(ctx, "verify_id_token")
	assert.NotEqual(t, ctx, callCtx, "the call runs under its own span")
	cause := &oidc.UpstreamError{Reason: oidc.UpstreamReasonIDToken, Timeout: true, Err: errors.New("context deadline exceeded")}
	done(cause)
	root.End()
	_, done = tm.StartUpstream(context.Background(), "discovery")
	done(nil)

	spans := tr.Spans()
	require.Len(t, spans, 2, "only the request and its call")
	sp := spans[1]
	assert.Equal(t, "upstream verify_id_token", sp.Name)
	assert.Equal(t, observe.SpanKindClient, sp.Kind)
	assert.Equal(t, "request", sp.Parent.Name)
	assert.Equal(t, map[string]any{"tempogate.upstream.op": "verify_id_token"}, sp.Attrs)
	assert.Equal(t, "timeout", sp.ErrorType)
	assert.Same(t, cause, sp.Err)
	assert.True(t, sp.Ended)
}
