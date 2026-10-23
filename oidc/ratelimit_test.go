package oidc_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/stretchr/testify/suite"

	"github.com/onhotpath/tempogate/oidc"
)

type rlClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *rlClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *rlClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type RateLimitSuite struct {
	suite.Suite

	clock *rlClock
}

func TestRateLimitSuite(t *testing.T) {
	suite.Run(t, new(RateLimitSuite))
}

func (s *RateLimitSuite) SetupTest() {
	s.clock = &rlClock{now: time.Unix(1700000000, 0)}
}

// handlerFor mounts stand-ins for the throttled operations (same operation
// IDs as the real handlers) plus one that is never throttled, behind the
// limiter's middleware.
func (s *RateLimitSuite) handlerFor(limits oidc.RateLimits, opts ...oidc.RateLimiterOption) http.Handler {
	rl := oidc.NewRateLimiter(append([]oidc.RateLimiterOption{
		oidc.WithRateLimits(limits),
		oidc.WithRateLimiterClock(s.clock.Now),
	}, opts...)...)

	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("test", "0.0.0"))
	api.UseMiddleware(rl.Middleware)
	ok := func(context.Context, *struct{}) (*struct{}, error) { return nil, nil }
	for _, op := range []struct{ id, method, path string }{
		{"authorize", http.MethodGet, oidc.AuthorizePath},
		{"device-authorization", http.MethodPost, oidc.DeviceAuthorizationPath},
		{"device-ui-submit", http.MethodPost, oidc.DevicePath},
		{"token", http.MethodPost, oidc.TokenPath},
		{"jwks", http.MethodGet, "/jwks"},
	} {
		huma.Register(api, huma.Operation{OperationID: op.id, Method: op.method, Path: op.path, DefaultStatus: http.StatusOK}, ok)
	}
	return mux
}

func (s *RateLimitSuite) do(h http.Handler, method, path, peer, xff string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, http.NoBody)
	req.RemoteAddr = peer
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func (s *RateLimitSuite) TestLimitsEachClientAddress() {
	h := s.handlerFor(oidc.RateLimits{Token: 2})

	for range 2 {
		s.Equal(http.StatusOK, s.do(h, http.MethodPost, "/token", "198.51.100.1:4000", "").Code)
	}
	rec := s.do(h, http.MethodPost, "/token", "198.51.100.1:4001", "")
	s.Equal(http.StatusTooManyRequests, rec.Code)
	s.Equal("30", rec.Header().Get("Retry-After"), "2/min refills one request every 30 s")
	s.Equal("application/json", rec.Header().Get("Content-Type"))
	var body struct {
		Error string `json:"error"`
		Desc  string `json:"error_description"`
	}
	s.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &body))
	s.Equal("temporarily_unavailable", body.Error)
	s.NotEmpty(body.Desc)

	s.Equal(http.StatusOK, s.do(h, http.MethodPost, "/token", "198.51.100.2:4000", "").Code,
		"another address has its own budget")

	s.clock.Advance(30 * time.Second)
	s.Equal(http.StatusOK, s.do(h, http.MethodPost, "/token", "198.51.100.1:4000", "").Code, "refilled")
	s.Equal(http.StatusTooManyRequests, s.do(h, http.MethodPost, "/token", "198.51.100.1:4000", "").Code)
}

func (s *RateLimitSuite) TestEndpointsHaveSeparateBudgets() {
	h := s.handlerFor(oidc.RateLimits{Authorize: 1, DeviceAuthorization: 1, DeviceVerification: 1, Token: 1})
	peer := "198.51.100.1:4000"
	for _, r := range []struct{ method, path string }{
		{http.MethodGet, "/authorize"},
		{http.MethodPost, "/device_authorization"},
		{http.MethodPost, "/device"},
		{http.MethodPost, "/token"},
	} {
		s.Equalf(http.StatusOK, s.do(h, r.method, r.path, peer, "").Code, "%s first", r.path)
		s.Equalf(http.StatusTooManyRequests, s.do(h, r.method, r.path, peer, "").Code, "%s second", r.path)
	}
	for range 5 {
		s.Equal(http.StatusOK, s.do(h, http.MethodGet, "/jwks", peer, "").Code, "other operations are never throttled")
	}
}

// Every rejection is reported by endpoint, never by client address, so the
// metric stays low-cardinality whatever the traffic.
func (s *RateLimitSuite) TestRejectionsAreObservedByEndpoint() {
	obs := newRecordingObserver()
	h := s.handlerFor(oidc.RateLimits{Authorize: 1, DeviceAuthorization: 1, DeviceVerification: 1, Token: 1},
		oidc.WithRateLimiterTelemetry(obs.Telemetry))
	for _, r := range []struct{ method, path string }{
		{http.MethodGet, "/authorize"},
		{http.MethodPost, "/device_authorization"},
		{http.MethodPost, "/device"},
		{http.MethodPost, "/token"},
	} {
		for range 2 {
			s.do(h, r.method, r.path, "198.51.100.1:4000", "")
		}
	}
	s.do(h, http.MethodGet, "/jwks", "198.51.100.1:4000", "")

	s.Equal([]string{"authorize", "device_authorization", "device_verification", "token"}, obs.rateLimitCalls())
}

func (s *RateLimitSuite) TestZeroDisablesAnEndpoint() {
	h := s.handlerFor(oidc.RateLimits{Authorize: 1})
	for range 5 {
		s.Equal(http.StatusOK, s.do(h, http.MethodPost, "/token", "198.51.100.1:4000", "").Code)
	}
	s.Equal(http.StatusOK, s.do(h, http.MethodGet, "/authorize", "198.51.100.1:4000", "").Code)
	s.Equal(http.StatusTooManyRequests, s.do(h, http.MethodGet, "/authorize", "198.51.100.1:4000", "").Code)
}

// TestVerificationPageGetsPlainText: POST /device is a browser form, so it
// gets a readable message rather than an OAuth JSON body.
func (s *RateLimitSuite) TestVerificationPageGetsPlainText() {
	h := s.handlerFor(oidc.RateLimits{DeviceVerification: 1})
	s.do(h, http.MethodPost, "/device", "198.51.100.1:4000", "")
	rec := s.do(h, http.MethodPost, "/device", "198.51.100.1:4000", "")
	s.Equal(http.StatusTooManyRequests, rec.Code)
	s.Equal("60", rec.Header().Get("Retry-After"))
	s.Contains(rec.Header().Get("Content-Type"), "text/plain")
	s.Contains(rec.Body.String(), "Too many")
}

func (s *RateLimitSuite) TestRetryAfterIsAtLeastOneSecond() {
	h := s.handlerFor(oidc.RateLimits{Token: 600})
	var rec *httptest.ResponseRecorder
	for range 601 {
		rec = s.do(h, http.MethodPost, "/token", "198.51.100.1:4000", "")
	}
	s.Equal(http.StatusTooManyRequests, rec.Code)
	s.Equal("1", rec.Header().Get("Retry-After"))
}

func (s *RateLimitSuite) TestSpoofedForwardedForFromUntrustedPeerIsIgnored() {
	h := s.handlerFor(oidc.RateLimits{Token: 2})
	// No trusted proxies: a client rotating X-Forwarded-For still shares
	// its own address's budget.
	s.Equal(http.StatusOK, s.do(h, http.MethodPost, "/token", "198.51.100.1:4000", "203.0.113.1").Code)
	s.Equal(http.StatusOK, s.do(h, http.MethodPost, "/token", "198.51.100.1:4000", "203.0.113.2").Code)
	s.Equal(http.StatusTooManyRequests, s.do(h, http.MethodPost, "/token", "198.51.100.1:4000", "203.0.113.3").Code)

	// Trusting some proxy does not extend that trust to other peers.
	h = s.handlerFor(oidc.RateLimits{Token: 2}, oidc.WithTrustedProxies(mustPrefixes(s, "10.0.0.0/8")))
	s.Equal(http.StatusOK, s.do(h, http.MethodPost, "/token", "198.51.100.1:4000", "203.0.113.1").Code)
	s.Equal(http.StatusOK, s.do(h, http.MethodPost, "/token", "198.51.100.1:4000", "203.0.113.2").Code)
	s.Equal(http.StatusTooManyRequests, s.do(h, http.MethodPost, "/token", "198.51.100.1:4000", "203.0.113.3").Code)
}

func (s *RateLimitSuite) TestTrustedProxyForwardsTheClientAddress() {
	h := s.handlerFor(oidc.RateLimits{Token: 1}, oidc.WithTrustedProxies(mustPrefixes(s, "10.0.0.0/8, 192.0.2.7")))
	proxy := "10.1.2.3:5000"

	s.Equal(http.StatusOK, s.do(h, http.MethodPost, "/token", proxy, "203.0.113.1").Code)
	s.Equal(http.StatusTooManyRequests, s.do(h, http.MethodPost, "/token", proxy, "203.0.113.1").Code)
	s.Equal(http.StatusOK, s.do(h, http.MethodPost, "/token", proxy, "203.0.113.2").Code,
		"clients behind the same proxy have their own budgets")

	// The client prepends its own X-Forwarded-For; the proxy appends the
	// real address. The rightmost untrusted entry wins, so the prefix the
	// client controls does not buy a fresh budget.
	s.Equal(http.StatusTooManyRequests, s.do(h, http.MethodPost, "/token", proxy, "198.51.100.77, 203.0.113.1").Code)

	// A chain of trusted hops (192.0.2.7 then 10.x) is walked past.
	s.Equal(http.StatusTooManyRequests, s.do(h, http.MethodPost, "/token", proxy, "203.0.113.2, 192.0.2.7").Code)
	s.Equal(http.StatusOK, s.do(h, http.MethodPost, "/token", proxy, "203.0.113.3, 192.0.2.7").Code)

	// Repeated headers are one list; a port on an entry is ignored.
	req := httptest.NewRequest(http.MethodPost, "/token", http.NoBody)
	req.RemoteAddr = proxy
	req.Header.Add("X-Forwarded-For", "198.51.100.9")
	req.Header.Add("X-Forwarded-For", "203.0.113.3:1234")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	s.Equal(http.StatusTooManyRequests, rec.Code)

	// A trusted peer without the header is the client itself.
	s.Equal(http.StatusOK, s.do(h, http.MethodPost, "/token", proxy, "").Code)
	s.Equal(http.StatusTooManyRequests, s.do(h, http.MethodPost, "/token", "10.1.2.3:5001", "").Code)

	// An unparseable entry ends the walk at the last address a trusted
	// proxy vouched for: the peer.
	s.Equal(http.StatusOK, s.do(h, http.MethodPost, "/token", "10.9.9.9:1", "not-an-ip").Code)
	s.Equal(http.StatusTooManyRequests, s.do(h, http.MethodPost, "/token", "10.9.9.9:1", "203.0.113.50, not-an-ip").Code)
}

func (s *RateLimitSuite) TestIPv6ClientsShareTheirSlash64() {
	h := s.handlerFor(oidc.RateLimits{Token: 1})
	s.Equal(http.StatusOK, s.do(h, http.MethodPost, "/token", "[2001:db8:1:2::1]:4000", "").Code)
	s.Equal(http.StatusTooManyRequests, s.do(h, http.MethodPost, "/token", "[2001:db8:1:2::ffff]:4000", "").Code)
	s.Equal(http.StatusOK, s.do(h, http.MethodPost, "/token", "[2001:db8:1:3::1]:4000", "").Code)
}

func (s *RateLimitSuite) TestParseTrustedProxies() {
	got, err := oidc.ParseTrustedProxies(" 10.0.0.0/8 ,192.0.2.7,2001:db8::/32,, ::1 ")
	s.Require().NoError(err)
	s.Equal([]netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("192.0.2.7/32"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("::1/128"),
	}, got)

	got, err = oidc.ParseTrustedProxies("")
	s.Require().NoError(err)
	s.Empty(got)

	for _, bad := range []string{"proxy.internal", "10.0.0.0/33", "10.0.0.1/8x"} {
		_, err := oidc.ParseTrustedProxies(bad)
		s.Errorf(err, "%q", bad)
	}
}

func (s *RateLimitSuite) TestNegativeLimitIsRejected() {
	s.Error(oidc.RateLimits{Token: -1}.Validate())
	s.NoError(oidc.RateLimits{}.Validate())
}

func mustPrefixes(s *RateLimitSuite, v string) []netip.Prefix {
	p, err := oidc.ParseTrustedProxies(v)
	s.Require().NoError(err)
	return p
}
