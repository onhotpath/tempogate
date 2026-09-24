package cli_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	"github.com/onhotpath/tempogate/cli"
)

// pollResp is one scripted response for the /token endpoint. status drives
// the HTTP status code; body is the verbatim JSON written. Test cases push a
// queue of these onto mockDeviceIssuer; the handler pops one per call.
type pollResp struct {
	status int
	body   string
}

// mockDeviceIssuer stands in for a running tempogate during DeviceFlow tests.
// It handles /device_authorization with one configurable response and /token
// with a per-test scripted queue so a single suite drives the happy path and
// every §3.5 error branch without forking the server.
type mockDeviceIssuer struct {
	srv *httptest.Server

	mu sync.Mutex

	initStatus int
	initBody   string

	pollQueue []pollResp
	pollCalls int

	gotDeviceCode string
	gotClientID   string
	gotGrantType  string
	gotScope      string
}

func newMockDeviceIssuer() *mockDeviceIssuer {
	m := &mockDeviceIssuer{
		initStatus: http.StatusOK,
		initBody: `{
  "device_code": "long-device-code-abc",
  "user_code": "BCDF-GHJK",
  "verification_uri": "https://tempogate.example.com/device",
  "verification_uri_complete": "https://tempogate.example.com/device?user_code=BCDF-GHJK",
  "expires_in": 900,
  "interval": 5
}`,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/device_authorization", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		m.mu.Lock()
		m.gotClientID = r.Form.Get("client_id")
		m.gotScope = r.Form.Get("scope")
		status, body := m.initStatus, m.initBody
		m.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		m.mu.Lock()
		m.gotDeviceCode = r.Form.Get("device_code")
		m.gotGrantType = r.Form.Get("grant_type")
		idx := m.pollCalls
		m.pollCalls++
		var resp pollResp
		if idx < len(m.pollQueue) {
			resp = m.pollQueue[idx]
		} else {
			// Past the end of the script: return authorization_pending so a
			// runaway loop spins (and is caught by the deadline) rather than
			// 200-OK'ing with an empty body.
			resp = pollResp{status: http.StatusBadRequest, body: `{"error":"authorization_pending"}`}
		}
		m.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.status)
		_, _ = w.Write([]byte(resp.body))
	})
	m.srv = httptest.NewServer(mux)
	return m
}

func (m *mockDeviceIssuer) close() { m.srv.Close() }

func (m *mockDeviceIssuer) setInit(status int, body string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.initStatus = status
	m.initBody = body
}

func (m *mockDeviceIssuer) script(queue ...pollResp) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pollQueue = queue
	m.pollCalls = 0
}

func (m *mockDeviceIssuer) calls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pollCalls
}

// mockClock is an injectable clock+sleep pair. now() advances each time
// sleep() is called so deadline arithmetic in DeviceFlow is observable
// without real wall-clock time. recorded captures sleep durations in order.
type mockClock struct {
	mu       sync.Mutex
	t        time.Time
	recorded []time.Duration
}

func newMockClock(start time.Time) *mockClock {
	return &mockClock{t: start}
}

func (c *mockClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *mockClock) sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	c.recorded = append(c.recorded, d)
	c.t = c.t.Add(d)
	c.mu.Unlock()
	return nil
}

func (c *mockClock) sleeps() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]time.Duration, len(c.recorded))
	copy(out, c.recorded)
	return out
}

type DeviceFlowSuite struct {
	suite.Suite

	issuer *mockDeviceIssuer
	clock  *mockClock
}

func TestDeviceFlowSuite(t *testing.T) {
	suite.Run(t, new(DeviceFlowSuite))
}

func (s *DeviceFlowSuite) SetupTest() {
	s.issuer = newMockDeviceIssuer()
	s.clock = newMockClock(time.Unix(1700000000, 0).UTC())
}

func (s *DeviceFlowSuite) TearDownTest() {
	s.issuer.close()
}

func (s *DeviceFlowSuite) newFlow(opts ...cli.DeviceOption) *cli.DeviceFlow {
	base := []cli.DeviceOption{
		cli.WithDeviceIssuer(s.issuer.srv.URL),
		cli.WithDeviceHTTPClient(s.issuer.srv.Client()),
		cli.WithDeviceClock(s.clock.now),
		cli.WithDeviceSleep(s.clock.sleep),
	}
	return cli.NewDeviceFlow(append(base, opts...)...)
}

// happyTokenBody is the canonical /token success response. Reused across
// tests so the token-shape assertions stay in one place.
const happyTokenBody = `{
  "access_token": "the.jwt.token",
  "refresh_token": "refresh-abc",
  "token_type": "Bearer",
  "expires_in": 14400
}`

func pendingResp() pollResp {
	return pollResp{status: http.StatusBadRequest, body: `{"error":"authorization_pending","error_description":"not yet approved"}`}
}

func slowDownResp() pollResp {
	return pollResp{status: http.StatusBadRequest, body: `{"error":"slow_down","error_description":"too fast"}`}
}

func successResp() pollResp {
	return pollResp{status: http.StatusOK, body: happyTokenBody}
}

func (s *DeviceFlowSuite) TestHappyPathPollsThenReturnsToken() {
	s.issuer.script(pendingResp(), pendingResp(), successResp())

	tok, err := s.newFlow().Run(context.Background())

	s.Require().NoError(err)
	s.Equal("the.jwt.token", tok.AccessToken)
	s.Equal("refresh-abc", tok.RefreshToken)
	s.Equal(3, s.issuer.calls(), "two pending polls plus the success")

	s.Equal("tempogate-device", s.issuer.gotClientID, "default device client_id")
	s.Equal("urn:ietf:params:oauth:grant-type:device_code", s.issuer.gotGrantType)
	s.Equal("long-device-code-abc", s.issuer.gotDeviceCode)

	sleeps := s.clock.sleeps()
	s.Require().Len(sleeps, 2, "one sleep between each of the two pending polls and the success")
	s.Equal(5*time.Second, sleeps[0])
	s.Equal(5*time.Second, sleeps[1])
}

func (s *DeviceFlowSuite) TestSlowDownBumpsIntervalByFiveSeconds() {
	// One slow_down, then success. The next sleep after slow_down must be
	// exactly the original interval + 5s (RFC 8628 §3.5).
	s.issuer.script(slowDownResp(), successResp())

	_, err := s.newFlow().Run(context.Background())
	s.Require().NoError(err)

	sleeps := s.clock.sleeps()
	s.Require().Len(sleeps, 1)
	s.Equal(10*time.Second, sleeps[0], "5s server interval + 5s slow_down bump")
}

func (s *DeviceFlowSuite) TestRepeatedSlowDownAccumulates() {
	// Each slow_down adds another +5s on top of the running interval.
	s.issuer.script(slowDownResp(), slowDownResp(), successResp())

	_, err := s.newFlow().Run(context.Background())
	s.Require().NoError(err)

	sleeps := s.clock.sleeps()
	s.Require().Len(sleeps, 2)
	s.Equal(10*time.Second, sleeps[0])
	s.Equal(15*time.Second, sleeps[1])
}

func (s *DeviceFlowSuite) TestSentinelErrorMapping() {
	cases := []struct {
		name string
		resp pollResp
		want error
	}{
		{
			name: "access_denied → ErrUserDenied",
			resp: pollResp{status: http.StatusBadRequest, body: `{"error":"access_denied"}`},
			want: cli.ErrUserDenied,
		},
		{
			name: "expired_token → ErrDeviceCodeExpired",
			resp: pollResp{status: http.StatusBadRequest, body: `{"error":"expired_token"}`},
			want: cli.ErrDeviceCodeExpired,
		},
		{
			name: "invalid_grant → ErrInvalidGrant",
			resp: pollResp{status: http.StatusBadRequest, body: `{"error":"invalid_grant"}`},
			want: cli.ErrInvalidGrant,
		},
		{
			name: "invalid_client → ErrInvalidClient",
			resp: pollResp{status: http.StatusUnauthorized, body: `{"error":"invalid_client"}`},
			want: cli.ErrInvalidClient,
		},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			// One fresh mock issuer per row keeps the response scripts and
			// call counters from leaking between table entries; the suite's
			// own SetupTest/TearDownTest remain responsible for the
			// outer-test fixture and are not re-entered here.
			issuer := newMockDeviceIssuer()
			defer issuer.close()
			issuer.script(tc.resp)

			flow := cli.NewDeviceFlow(
				cli.WithDeviceIssuer(issuer.srv.URL),
				cli.WithDeviceHTTPClient(issuer.srv.Client()),
				cli.WithDeviceClock(s.clock.now),
				cli.WithDeviceSleep(s.clock.sleep),
			)
			_, err := flow.Run(context.Background())
			s.Require().Error(err)
			s.True(errors.Is(err, tc.want), "got %v, want errors.Is(%v)", err, tc.want)
		})
	}
}

func (s *DeviceFlowSuite) TestContextCancellationExitsImmediately() {
	// pre-cancelled context: the loop's first ctx.Err() check returns before
	// any poll round-trip is made.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	s.issuer.script(successResp())

	_, err := s.newFlow().Run(ctx)
	s.Require().Error(err)
	s.True(errors.Is(err, context.Canceled))
	s.Equal(0, s.issuer.calls(), "no poll should be made after cancellation")
}

func (s *DeviceFlowSuite) TestContextCancelMidLoopBlocksFurtherPolls() {
	// One pending response, then we cancel via a sleep that returns
	// context.Canceled. No further polls should occur.
	s.issuer.script(pendingResp(), successResp())

	cancellingSleep := func(_ context.Context, _ time.Duration) error {
		return context.Canceled
	}

	_, err := s.newFlow(cli.WithDeviceSleep(cancellingSleep)).Run(context.Background())
	s.Require().Error(err)
	s.True(errors.Is(err, context.Canceled))
	s.Equal(1, s.issuer.calls(), "only the first poll should have run")
}

func (s *DeviceFlowSuite) TestPollDeadlineExceeded() {
	// Short deadline + endless pending responses: the loop should exit with
	// ErrPollDeadlineExceeded on the first iteration whose elapsed time
	// crosses the deadline.
	s.issuer.script(pendingResp(), pendingResp(), pendingResp())

	_, err := s.newFlow(cli.WithDevicePollDeadline(3 * time.Second)).Run(context.Background())
	s.Require().Error(err)
	s.True(errors.Is(err, cli.ErrPollDeadlineExceeded), "got %v", err)
}

func (s *DeviceFlowSuite) TestTransientErrorBackoffIsExponential() {
	// Two 503s, then success. Backoff should be interval, then interval*2.
	s.issuer.script(
		pollResp{status: http.StatusServiceUnavailable, body: "upstream down"},
		pollResp{status: http.StatusServiceUnavailable, body: "still down"},
		successResp(),
	)

	_, err := s.newFlow().Run(context.Background())
	s.Require().NoError(err)

	sleeps := s.clock.sleeps()
	s.Require().Len(sleeps, 2)
	s.Equal(5*time.Second, sleeps[0], "first transient sleep is the interval")
	s.Equal(10*time.Second, sleeps[1], "second transient doubles")
}

func (s *DeviceFlowSuite) TestTransientErrorBackoffCapsAtFourTimesInterval() {
	// Four 502s then success: backoff sequence is interval, 2x, 4x, 4x.
	s.issuer.script(
		pollResp{status: http.StatusBadGateway, body: "down"},
		pollResp{status: http.StatusBadGateway, body: "down"},
		pollResp{status: http.StatusBadGateway, body: "down"},
		pollResp{status: http.StatusBadGateway, body: "down"},
		successResp(),
	)

	_, err := s.newFlow().Run(context.Background())
	s.Require().NoError(err)

	sleeps := s.clock.sleeps()
	s.Require().Len(sleeps, 4)
	s.Equal(5*time.Second, sleeps[0])
	s.Equal(10*time.Second, sleeps[1])
	s.Equal(20*time.Second, sleeps[2])
	s.Equal(20*time.Second, sleeps[3], "capped at interval × 4")
}

func (s *DeviceFlowSuite) TestPendingResetsBackoffAfterTransient() {
	// 502, then pending. The pending response must reset the backoff so the
	// next sleep is the plain interval, not the doubled-from-transient value.
	s.issuer.script(
		pollResp{status: http.StatusBadGateway, body: "down"},
		pendingResp(),
		successResp(),
	)

	_, err := s.newFlow().Run(context.Background())
	s.Require().NoError(err)

	sleeps := s.clock.sleeps()
	s.Require().Len(sleeps, 2)
	s.Equal(5*time.Second, sleeps[0], "first transient sleep")
	s.Equal(5*time.Second, sleeps[1], "pending resets the backoff to the plain interval")
}

func (s *DeviceFlowSuite) TestIntervalFloorClampsZeroToMinSleep() {
	s.issuer.setInit(http.StatusOK, `{
  "device_code": "long-device-code-abc",
  "user_code": "BCDF-GHJK",
  "verification_uri": "https://tempogate.example.com/device",
  "verification_uri_complete": "https://tempogate.example.com/device?user_code=BCDF-GHJK",
  "expires_in": 900,
  "interval": 0
}`)
	s.issuer.script(pendingResp(), successResp())

	_, err := s.newFlow().Run(context.Background())
	s.Require().NoError(err)

	sleeps := s.clock.sleeps()
	s.Require().Len(sleeps, 1)
	s.Equal(time.Second, sleeps[0], "interval=0 clamps to the default 1s minSleep")
}

func (s *DeviceFlowSuite) TestCustomMinSleepIsHonoured() {
	s.issuer.setInit(http.StatusOK, `{
  "device_code": "long-device-code-abc",
  "user_code": "BCDF-GHJK",
  "verification_uri": "https://tempogate.example.com/device",
  "verification_uri_complete": "https://tempogate.example.com/device?user_code=BCDF-GHJK",
  "expires_in": 900,
  "interval": 0
}`)
	s.issuer.script(pendingResp(), successResp())

	_, err := s.newFlow(cli.WithDeviceMinSleep(2 * time.Second)).Run(context.Background())
	s.Require().NoError(err)

	sleeps := s.clock.sleeps()
	s.Require().Len(sleeps, 1)
	s.Equal(2*time.Second, sleeps[0])
}

func (s *DeviceFlowSuite) TestPromptIncludesUserCodeAndVerificationURIs() {
	s.issuer.script(successResp())

	var out strings.Builder
	_, err := s.newFlow(cli.WithDeviceOutput(&out)).Run(context.Background())
	s.Require().NoError(err)

	got := out.String()
	s.Contains(got, "BCDF-GHJK", "user_code must be printed")
	s.Contains(got, "https://tempogate.example.com/device", "verification_uri must be printed")
	s.Contains(got, "https://tempogate.example.com/device?user_code=BCDF-GHJK", "verification_uri_complete must be printed")
	s.Contains(got, "Waiting for you to approve")
}

func (s *DeviceFlowSuite) TestPromptOmitsCompleteURIWhenServerOmitsIt() {
	s.issuer.setInit(http.StatusOK, `{
  "device_code": "long-device-code-abc",
  "user_code": "BCDF-GHJK",
  "verification_uri": "https://tempogate.example.com/device",
  "expires_in": 900,
  "interval": 5
}`)
	s.issuer.script(successResp())

	var out strings.Builder
	_, err := s.newFlow(cli.WithDeviceOutput(&out)).Run(context.Background())
	s.Require().NoError(err)

	s.NotContains(out.String(), "scan/open", "the optional-URI paragraph must be silenced when the server omitted verification_uri_complete")
}

func (s *DeviceFlowSuite) TestCustomClientIDAndScopeArePropagated() {
	s.issuer.script(successResp())

	_, err := s.newFlow(
		cli.WithDeviceClientID("my-cli"),
		cli.WithDeviceScope("openid email profile"),
	).Run(context.Background())
	s.Require().NoError(err)

	s.Equal("my-cli", s.issuer.gotClientID)
	s.Equal("openid email profile", s.issuer.gotScope)
}

func (s *DeviceFlowSuite) TestEmptyClientIDOptionDoesNotOverrideDefault() {
	s.issuer.script(successResp())

	_, err := s.newFlow(cli.WithDeviceClientID("")).Run(context.Background())
	s.Require().NoError(err)

	s.Equal("tempogate-device", s.issuer.gotClientID)
}

func (s *DeviceFlowSuite) TestMissingIssuerIsRejected() {
	_, err := cli.NewDeviceFlow().Run(context.Background())
	s.Require().Error(err)
	s.Contains(err.Error(), "issuer is required")
}

func (s *DeviceFlowSuite) TestInitInvalidClientIsMappedToSentinel() {
	s.issuer.setInit(http.StatusUnauthorized, `{"error":"invalid_client","error_description":"unknown client"}`)

	_, err := s.newFlow().Run(context.Background())
	s.Require().Error(err)
	s.True(errors.Is(err, cli.ErrInvalidClient))
}

func (s *DeviceFlowSuite) TestInitOtherErrorPreservesDiagnostic() {
	s.issuer.setInit(http.StatusBadRequest, `{"error":"invalid_request","error_description":"missing client_id"}`)

	_, err := s.newFlow().Run(context.Background())
	s.Require().Error(err)
	s.Contains(err.Error(), "invalid_request")
	s.Contains(err.Error(), "missing client_id")
}

func (s *DeviceFlowSuite) TestInitNonOAuthErrorReportsStatus() {
	s.issuer.setInit(http.StatusInternalServerError, "boom")

	_, err := s.newFlow().Run(context.Background())
	s.Require().Error(err)
	s.Contains(err.Error(), "HTTP 500")
}

func (s *DeviceFlowSuite) TestInitMalformedSuccessJSONIsRejected() {
	s.issuer.setInit(http.StatusOK, `{not json}`)

	_, err := s.newFlow().Run(context.Background())
	s.Require().Error(err)
	s.Contains(err.Error(), "decode device authorization response")
}

func (s *DeviceFlowSuite) TestInitMissingDeviceCodeIsRejected() {
	s.issuer.setInit(http.StatusOK, `{"user_code":"BCDF-GHJK","verification_uri":"https://x","expires_in":900,"interval":5}`)

	_, err := s.newFlow().Run(context.Background())
	s.Require().Error(err)
	s.Contains(err.Error(), "missing device_code")
}

func (s *DeviceFlowSuite) TestPollMalformedTokenJSONIsRejected() {
	s.issuer.script(pollResp{status: http.StatusOK, body: "<<< not json >>>"})

	_, err := s.newFlow().Run(context.Background())
	s.Require().Error(err)
	s.Contains(err.Error(), "decode token response")
}

func (s *DeviceFlowSuite) TestPollTokenResponseWithoutAccessTokenIsRejected() {
	s.issuer.script(pollResp{status: http.StatusOK, body: `{"token_type":"Bearer","expires_in":14400}`})

	_, err := s.newFlow().Run(context.Background())
	s.Require().Error(err)
	s.Contains(err.Error(), "no access_token")
}

func (s *DeviceFlowSuite) TestPollNonOAuthFourxxIncludesBody() {
	s.issuer.script(pollResp{status: http.StatusForbidden, body: "you shall not pass"})

	_, err := s.newFlow().Run(context.Background())
	s.Require().Error(err)
	s.Contains(err.Error(), "HTTP 403")
	s.Contains(err.Error(), "you shall not pass")
}

func (s *DeviceFlowSuite) TestPollUnknownOAuthErrorIncludesDiagnostic() {
	s.issuer.script(pollResp{status: http.StatusBadRequest, body: `{"error":"weird_error","error_description":"unexpected"}`})

	_, err := s.newFlow().Run(context.Background())
	s.Require().Error(err)
	s.Contains(err.Error(), "weird_error")
	s.Contains(err.Error(), "unexpected")
}

func (s *DeviceFlowSuite) TestTokenExpiryComputedFromInjectedClock() {
	// The token's absolute ExpiresAt must be (clock + expires_in). Because
	// the mock clock advances by exactly one 5s sleep before the successful
	// poll, the expected anchor is start + 5s.
	s.issuer.script(pendingResp(), successResp())

	start := s.clock.now()
	tok, err := s.newFlow().Run(context.Background())
	s.Require().NoError(err)

	want := start.Add(5 * time.Second).Add(4 * time.Hour)
	s.Equal(want, tok.ExpiresAt)
}

func (s *DeviceFlowSuite) TestNetworkErrorDuringInitIsSurfaced() {
	// Point at a closed server: Do returns an error.
	s.issuer.close() // close before the run
	_, err := s.newFlow().Run(context.Background())
	s.Require().Error(err)
	s.Contains(err.Error(), "device authorization request")
}

func (s *DeviceFlowSuite) TestNetworkErrorDuringPollIsTreatedAsTransient() {
	// First /token call hijacks + closes the connection (network error); the
	// second returns success. The transient should back off and resume.
	calls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/device_authorization", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(s.issuer.initBody))
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls == 1 {
			hj, ok := w.(http.Hijacker)
			s.Require().True(ok)
			conn, _, hErr := hj.Hijack()
			s.Require().NoError(hErr)
			_ = conn.Close()
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(happyTokenBody))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	tok, err := cli.NewDeviceFlow(
		cli.WithDeviceIssuer(srv.URL),
		cli.WithDeviceHTTPClient(srv.Client()),
		cli.WithDeviceClock(s.clock.now),
		cli.WithDeviceSleep(s.clock.sleep),
	).Run(context.Background())

	s.Require().NoError(err, "transient network error should not abort the flow")
	s.Equal("the.jwt.token", tok.AccessToken)
	s.Equal(2, calls)
	sleeps := s.clock.sleeps()
	s.Require().Len(sleeps, 1)
	s.Equal(5*time.Second, sleeps[0], "first transient sleeps the plain interval")
}

func (s *DeviceFlowSuite) TestPollDeadlineFallsBackToServerExpiresIn() {
	// No WithDevicePollDeadline; server says expires_in=10. After enough
	// pending polls the elapsed-time check should fire ErrPollDeadlineExceeded.
	s.issuer.setInit(http.StatusOK, `{
  "device_code": "long-device-code-abc",
  "user_code": "BCDF-GHJK",
  "verification_uri": "https://tempogate.example.com/device",
  "expires_in": 10,
  "interval": 5
}`)
	s.issuer.script(pendingResp(), pendingResp(), pendingResp(), pendingResp())

	_, err := s.newFlow().Run(context.Background())
	s.Require().Error(err)
	s.True(errors.Is(err, cli.ErrPollDeadlineExceeded))
}

// TestDefaultsCompose validates that the constructor returns a working flow
// without any options when given just the bare minimum (issuer + HTTP client
// pointed at the mock server + clock + sleep). Catches a regression where a
// default ever silently becomes nil.
func (s *DeviceFlowSuite) TestDefaultsCompose() {
	s.issuer.script(successResp())

	tok, err := cli.NewDeviceFlow(
		cli.WithDeviceIssuer(s.issuer.srv.URL),
		cli.WithDeviceHTTPClient(s.issuer.srv.Client()),
		cli.WithDeviceClock(s.clock.now),
		cli.WithDeviceSleep(s.clock.sleep),
	).Run(context.Background())

	s.Require().NoError(err)
	s.Equal("the.jwt.token", tok.AccessToken)
}

// Helper: ensure happyTokenBody is valid JSON; a typo there would mask test
// failures by surfacing as decode errors rather than the intended assertions.
func TestHappyTokenBodyIsValidJSON(t *testing.T) {
	var v map[string]any
	if err := json.Unmarshal([]byte(happyTokenBody), &v); err != nil {
		t.Fatalf("happyTokenBody is not valid JSON: %v", err)
	}
}

// TestDefaultSleepRespectsContext exercises the production sleep seam
// directly: a normal positive duration must return nil, a pre-cancelled
// context must return ctx.Err() without sleeping, and a zero/negative
// duration must return immediately (still respecting an already-cancelled
// context).
func TestDefaultSleepRespectsContext(t *testing.T) {
	t.Run("positive duration returns nil", func(t *testing.T) {
		err := cli.DefaultSleep(context.Background(), time.Millisecond)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
	})
	t.Run("cancellation while sleeping returns ctx.Err()", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(5 * time.Millisecond)
			cancel()
		}()
		err := cli.DefaultSleep(ctx, time.Hour)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	})
	t.Run("zero duration with live context returns nil", func(t *testing.T) {
		if err := cli.DefaultSleep(context.Background(), 0); err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
	})
	t.Run("zero duration with cancelled context returns ctx.Err()", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := cli.DefaultSleep(ctx, 0); !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	})
}
