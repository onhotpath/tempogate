package google_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"
	"golang.org/x/oauth2"

	"github.com/onhotpath/tempogate/observe/observetest"
	"github.com/onhotpath/tempogate/oidc"
	"github.com/onhotpath/tempogate/oidc/connector/google"
)

const (
	testClientID = "client-123.apps.googleusercontent.com"
	testKID      = "google-test-key"
	testVerifier = "test-pkce-verifier-0123456789abcdefghijklmnop"
	testNonce    = "test-upstream-nonce"
	testRedirect = "https://tempogate.example.com/callback/google"
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
	gotRedirect string

	// discoveryDown makes the discovery document answer 503, modelling a
	// transient outage of the IdP's well-known endpoint.
	discoveryDown atomic.Bool

	// stalled maps a path to the way it hangs ("headers": never answers;
	// "body": sends headers, then trickles the body forever). Either holds
	// the request until the client gives up.
	stalled sync.Map
	// delay, in nanoseconds, slows every response down by that much.
	delay atomic.Int64
}

const (
	stallHeaders = "headers"
	stallBody    = "body"
)

func (i *idp) stall(path, how string) { i.stalled.Store(path, how) }

func (i *idp) unstall(path string) { i.stalled.Delete(path) }

// withStalls hangs the paths stall marks, ahead of the real handlers.
func (i *idp) withStalls(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(time.Duration(i.delay.Load()))
		how, ok := i.stalled.Load(r.URL.Path)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}
		// The server notices the client hanging up only once the request
		// body is consumed; until then a stalled POST would outlive it.
		_, _ = io.Copy(io.Discard, r.Body)
		if how == stallBody {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("{"))
		}
		tick := time.NewTicker(20 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-r.Context().Done():
				return
			case <-tick.C:
				if how == stallBody {
					_, _ = w.Write([]byte(" "))
					w.(http.Flusher).Flush()
				}
			}
		}
	})
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
		i.gotRedirect = r.Form.Get("redirect_uri")
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
	srv = httptest.NewServer(i.withStalls(mux))
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
		srv.URL)
}

func (s *GoogleSuite) TestHappyPath() {
	i := newIDP(s.T())
	srv := i.server(s.T())
	c := s.clientFor(srv)

	id, err := c.ExchangeAndVerify(s.ctx, "code", testRedirect, testVerifier, testNonce)
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

	id, err := c.ExchangeAndVerify(s.ctx, "code", testRedirect, testVerifier, testNonce)
	s.Require().NoError(err)
	s.Equal("example.com", id.HostedDomain)
}

func (s *GoogleSuite) TestMissingSubjectIsRejected() {
	i := newIDP(s.T())
	i.sub = ""
	srv := i.server(s.T())
	c := s.clientFor(srv)

	_, err := c.ExchangeAndVerify(s.ctx, "code", testRedirect, testVerifier, testNonce)
	s.Require().Error(err)
	s.Contains(err.Error(), "sub")
}

func (s *GoogleSuite) TestMissingEmailIsRejected() {
	i := newIDP(s.T())
	i.email = ""
	srv := i.server(s.T())
	c := s.clientFor(srv)

	_, err := c.ExchangeAndVerify(s.ctx, "code", testRedirect, testVerifier, testNonce)
	s.Require().Error(err)
	s.Contains(err.Error(), "email")
}

func (s *GoogleSuite) TestExchangeFailure() {
	i := newIDP(s.T())
	i.failExchange = true
	srv := i.server(s.T())
	c := s.clientFor(srv)

	_, err := c.ExchangeAndVerify(s.ctx, "code", testRedirect, testVerifier, testNonce)
	s.Require().Error(err)
	s.Contains(err.Error(), "code exchange")
}

func (s *GoogleSuite) TestMissingIDToken() {
	i := newIDP(s.T())
	i.omitIDToken = true
	srv := i.server(s.T())
	c := s.clientFor(srv)

	_, err := c.ExchangeAndVerify(s.ctx, "code", testRedirect, testVerifier, testNonce)
	s.Require().Error(err)
	s.Contains(err.Error(), "missing id_token")
}

func (s *GoogleSuite) TestPKCEVerifierIsSentToTokenEndpoint() {
	i := newIDP(s.T())
	srv := i.server(s.T())
	c := s.clientFor(srv)

	_, err := c.ExchangeAndVerify(s.ctx, "code", testRedirect, testVerifier, testNonce)
	s.Require().NoError(err)
	i.mu.Lock()
	defer i.mu.Unlock()
	s.Equal(testVerifier, i.gotVerifier)
	s.Equal(testRedirect, i.gotRedirect, "the code is redeemed for the redirect URI it was issued to")
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

			_, err := c.ExchangeAndVerify(s.ctx, "code", testRedirect, testVerifier, testNonce)
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

			_, err := c.ExchangeAndVerify(s.ctx, "code", testRedirect, testVerifier, testNonce)
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

	_, err := c.ExchangeAndVerify(s.ctx, "code", testRedirect, testVerifier, testNonce)
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
		srv.URL,
		google.WithClock(func() time.Time { return now }))
	discoveries := func() int32 { return atomic.LoadInt32(&i.discoveryN) }

	i.discoveryDown.Store(true)
	_, err := c.ExchangeAndVerify(s.ctx, "code", testRedirect, testVerifier, testNonce)
	s.Require().Error(err)
	s.Equal(oidc.UpstreamReasonDiscovery, reasonOf(err))
	s.EqualValues(1, discoveries())

	now = t0.Add(500 * time.Millisecond)
	_, err = c.ExchangeAndVerify(s.ctx, "code", testRedirect, testVerifier, testNonce)
	s.Equal(oidc.UpstreamReasonDiscovery, reasonOf(err))
	s.EqualValues(1, discoveries(), "inside the backoff window the failure is served without a request")

	now = t0.Add(time.Second)
	_, err = c.ExchangeAndVerify(s.ctx, "code", testRedirect, testVerifier, testNonce)
	s.Equal(oidc.UpstreamReasonDiscovery, reasonOf(err))
	s.EqualValues(2, discoveries(), "the backoff window elapsed, so discovery is retried")

	i.discoveryDown.Store(false)
	now = t0.Add(2500 * time.Millisecond)
	_, err = c.ExchangeAndVerify(s.ctx, "code", testRedirect, testVerifier, testNonce)
	s.Equal(oidc.UpstreamReasonDiscovery, reasonOf(err))
	s.EqualValues(2, discoveries(), "the backoff doubled after the second failure")

	now = t0.Add(3 * time.Second)
	id, err := c.ExchangeAndVerify(s.ctx, "code", testRedirect, testVerifier, testNonce)
	s.Require().NoError(err, "discovery recovers once the IdP is back, without a restart")
	s.Equal("sub-1", id.Subject)
	s.EqualValues(3, discoveries())

	_, err = c.ExchangeAndVerify(s.ctx, "code", testRedirect, testVerifier, testNonce)
	s.Require().NoError(err)
	s.EqualValues(3, discoveries(), "a successful discovery is cached")
}

func (s *GoogleSuite) TestDiscoveryBackoffIsCapped() {
	i := newIDP(s.T())
	srv := i.server(s.T())
	now := time.Unix(1700000000, 0)
	c := google.New(testClientID, "secret", srv.URL+"/token",
		srv.URL,
		google.WithClock(func() time.Time { return now }))
	i.discoveryDown.Store(true)

	// Fail an hour apart, so every call retries and the backoff keeps
	// doubling well past any sane cap.
	for range 12 {
		_, err := c.ExchangeAndVerify(s.ctx, "code", testRedirect, testVerifier, testNonce)
		s.Require().Error(err)
		now = now.Add(time.Hour)
	}
	n := atomic.LoadInt32(&i.discoveryN)

	i.discoveryDown.Store(false)
	now = now.Add(time.Minute)
	_, err := c.ExchangeAndVerify(s.ctx, "code", testRedirect, testVerifier, testNonce)
	s.Require().NoError(err, "after a long outage, recovery is at most a minute away")
	s.EqualValues(n+1, atomic.LoadInt32(&i.discoveryN))
}

// testTimeout stands in for the 10s production timeout; stallBound is how
// long a call may take against a stalled IdP before the test calls it hung.
const (
	testTimeout = 200 * time.Millisecond
	stallBound  = 5 * time.Second
)

// exchangeWithin runs ExchangeAndVerify and fails the test if it does not
// return within stallBound, rather than hanging the suite.
func (s *GoogleSuite) exchangeWithin(c *google.Client) error {
	done := make(chan error, 1)
	go func() {
		_, err := c.ExchangeAndVerify(s.ctx, "code", testRedirect, testVerifier, testNonce)
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(stallBound):
		s.FailNow("ExchangeAndVerify still blocked on a stalled upstream", "after %s", stallBound)
		return nil
	}
}

// A stalled or trickling Google must fail the login within the upstream
// timeout, as the reason of the call that hung, flagged as a timeout. The
// request context has no deadline here, as with a browser that keeps
// waiting: before the client had its own bound, each of these blocked until
// the browser hung up.
func (s *GoogleSuite) TestStalledUpstreamTimesOut() {
	cases := []struct {
		name, path, how, reason, op string
	}{
		{"discovery never answers", "/.well-known/openid-configuration", stallHeaders, oidc.UpstreamReasonDiscovery, "discovery"},
		{"discovery trickles its body", "/.well-known/openid-configuration", stallBody, oidc.UpstreamReasonDiscovery, "discovery"},
		{"token endpoint never answers", "/token", stallHeaders, oidc.UpstreamReasonExchange, "code_exchange"},
		{"token endpoint trickles its body", "/token", stallBody, oidc.UpstreamReasonExchange, "code_exchange"},
		{"JWKS never answers", "/jwks", stallHeaders, oidc.UpstreamReasonIDToken, "verify_id_token"},
		{"JWKS trickles its body", "/jwks", stallBody, oidc.UpstreamReasonIDToken, "verify_id_token"},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			i := newIDP(s.T())
			i.stall(tc.path, tc.how)
			c, obs := s.observedClientFor(i.server(s.T()), google.WithTimeout(testTimeout))

			start := time.Now()
			err := s.exchangeWithin(c)
			took := time.Since(start)

			var ue *oidc.UpstreamError
			s.Require().ErrorAs(err, &ue)
			s.Equal(tc.reason, ue.Reason)
			s.True(ue.Timeout, "a call that got no answer in time is flagged as a timeout")
			s.GreaterOrEqual(took, testTimeout, "the call is given its full budget")
			s.Contains(obs.calls(), tc.op+"/timeout")
		})
	}
}

// Every call gets its own budget: a login whose discovery, exchange and
// JWKS fetch each take most of the timeout (together well over it) still
// succeeds.
func (s *GoogleSuite) TestTimeoutIsPerCall() {
	i := newIDP(s.T())
	const budget = time.Second
	i.delay.Store(int64(budget * 6 / 10))
	srv := i.server(s.T())
	c := google.New(testClientID, "secret", srv.URL+"/token",
		srv.URL, google.WithTimeout(budget))
	s.Require().NoError(s.exchangeWithin(c))
}

// A discovery timeout is a failure like any other: retried after the
// backoff, never cached until restart.
func (s *GoogleSuite) TestDiscoveryTimeoutIsNotCached() {
	i := newIDP(s.T())
	i.stall("/.well-known/openid-configuration", stallHeaders)
	t0 := time.Unix(1700000000, 0)
	now := t0
	srv := i.server(s.T())
	c := google.New(testClientID, "secret", srv.URL+"/token",
		srv.URL,
		google.WithTimeout(testTimeout), google.WithClock(func() time.Time { return now }))

	err := s.exchangeWithin(c)
	s.Require().Error(err)
	s.Equal(oidc.UpstreamReasonDiscovery, reasonOf(err))

	i.unstall("/.well-known/openid-configuration")
	now = t0.Add(time.Second)
	s.Require().NoError(s.exchangeWithin(c), "discovery must be retried once the backoff elapses")
}

// The JWKS fetch runs on a context the provider kept from discovery, after
// that discovery call's deadline has passed. It must still go through, and
// be bounded by, the upstream client, and a timed-out fetch must not poison
// later ones.
func (s *GoogleSuite) TestJWKSRecoversAfterTimeout() {
	i := newIDP(s.T())
	srv := i.server(s.T())
	c := google.New(testClientID, "secret", srv.URL+"/token",
		srv.URL, google.WithTimeout(testTimeout))

	i.stall("/jwks", stallHeaders)
	err := s.exchangeWithin(c)
	s.Require().Error(err)
	s.Equal(oidc.UpstreamReasonIDToken, reasonOf(err))

	i.unstall("/jwks")
	s.Require().NoError(s.exchangeWithin(c), "a later login must fetch the JWKS afresh")
}

func reasonOf(err error) string {
	var ue *oidc.UpstreamError
	if errors.As(err, &ue) {
		return ue.Reason
	}
	return ""
}

// recordingObserver is an *oidc.Telemetry over an in-memory meter.
type recordingObserver struct {
	*oidc.Telemetry
	meter *observetest.Meter
}

func newRecordingObserver(t testing.TB) *recordingObserver {
	m := observetest.NewMeter()
	tm, err := oidc.NewTelemetry(m)
	require.NoError(t, err)
	return &recordingObserver{Telemetry: tm, meter: m}
}

// calls reads every timed upstream call back as "op/outcome": ok, or the
// error reason it was counted with, plus "/untimed" if it took no time.
func (r *recordingObserver) calls() []string {
	var out []string
	for _, m := range r.meter.Measurements("tempogate.upstream_request.duration", "tempogate.upstream_errors") {
		if m.Name == "tempogate.upstream_errors" {
			// Counted right after its call's duration.
			out[len(out)-1] = strings.Replace(out[len(out)-1], "/ok", "/"+m.Attrs["reason"], 1)
			continue
		}
		call := m.Attrs["op"] + "/ok"
		if m.Value <= 0 {
			call += "/untimed"
		}
		out = append(out, call)
	}
	return out
}

func (s *GoogleSuite) observedClientFor(srv *httptest.Server, opts ...google.Option) (*google.Client, *recordingObserver) {
	obs := newRecordingObserver(s.T())
	return google.New(testClientID, "secret", srv.URL+"/token",
		srv.URL, append(opts, google.WithTelemetry(obs.Telemetry))...), obs
}

// Every upstream round-trip is timed by operation, so a slow or failing
// Google shows up per leg. Discovery runs first and is then cached.
func (s *GoogleSuite) TestUpstreamCallsAreObserved() {
	srv := newIDP(s.T()).server(s.T())
	c, obs := s.observedClientFor(srv)

	_, err := c.ExchangeAndVerify(s.ctx, "code", testRedirect, testVerifier, testNonce)
	s.Require().NoError(err)
	_, err = c.ExchangeAndVerify(s.ctx, "code", testRedirect, testVerifier, testNonce)
	s.Require().NoError(err)

	s.Equal([]string{
		"discovery/ok", "code_exchange/ok", "verify_id_token/ok",
		"code_exchange/ok", "verify_id_token/ok",
	}, obs.calls())
}

func (s *GoogleSuite) TestUpstreamFailureIsObserved() {
	i := newIDP(s.T())
	i.failExchange = true
	c, obs := s.observedClientFor(i.server(s.T()))

	_, err := c.ExchangeAndVerify(s.ctx, "code", testRedirect, testVerifier, testNonce)
	s.Require().Error(err)

	s.Equal([]string{"discovery/ok", "code_exchange/error"}, obs.calls())
}

// A failed discovery is observed once per attempt that reaches the IdP; a
// failure served from inside the backoff window is not a call to Google.
func (s *GoogleSuite) TestDiscoveryRetriesAreObserved() {
	i := newIDP(s.T())
	t0 := time.Unix(1700000000, 0)
	now := t0
	c, obs := s.observedClientFor(i.server(s.T()), google.WithClock(func() time.Time { return now }))

	i.discoveryDown.Store(true)
	_, err := c.ExchangeAndVerify(s.ctx, "code", testRedirect, testVerifier, testNonce)
	s.Require().Error(err)
	now = t0.Add(500 * time.Millisecond)
	_, err = c.ExchangeAndVerify(s.ctx, "code", testRedirect, testVerifier, testNonce)
	s.Require().Error(err)

	i.discoveryDown.Store(false)
	now = t0.Add(time.Second)
	_, err = c.ExchangeAndVerify(s.ctx, "code", testRedirect, testVerifier, testNonce)
	s.Require().NoError(err)

	s.Equal([]string{
		"discovery/error",
		"discovery/ok", "code_exchange/ok", "verify_id_token/ok",
	}, obs.calls())
}

// TestFxWiresTheTelemetry proves google.Fx hands the graph's *oidc.Telemetry
// to the connector it contributes, so upstream calls made through the real
// wiring are counted.
func TestFxWiresTheTelemetry(t *testing.T) {
	srv := newIDP(t).server(t)
	obs := newRecordingObserver(t)
	var conns struct {
		fx.In
		All []oidc.Connector `group:"oidc_connectors"`
	}
	fxtest.New(t,
		google.Fx(),
		fx.Supply(obs.Telemetry),
		fx.Supply(slog.New(slog.DiscardHandler)),
		fx.Supply(
			fx.Annotate(testClientID, fx.ResultTags(`name:"google_client_id"`)),
			fx.Annotate("secret", fx.ResultTags(`name:"google_client_secret"`)),
			fx.Annotate(srv.URL+"/auth", fx.ResultTags(`name:"google_auth_endpoint"`)),
			fx.Annotate(srv.URL+"/token", fx.ResultTags(`name:"google_token_endpoint"`)),
			fx.Annotate(srv.URL, fx.ResultTags(`name:"google_issuer_url"`)),
			fx.Annotate("", fx.ResultTags(`name:"oidc_allowed_hosted_domains"`)),
		),
		fx.Populate(&conns),
	).RequireStart().RequireStop()

	require.Len(t, conns.All, 1)
	_, err := conns.All[0].Complete(context.Background(), oidc.CompleteParams{
		RedirectURI:  testRedirect,
		Params:       url.Values{"code": {"code"}},
		CodeVerifier: testVerifier,
		Nonce:        testNonce,
	})
	require.NoError(t, err)
	require.Equal(t, []string{"discovery/ok", "code_exchange/ok", "verify_id_token/ok"}, obs.calls())
}
