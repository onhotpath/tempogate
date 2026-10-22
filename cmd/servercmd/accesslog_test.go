package servercmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

type AccessLogSuite struct {
	suite.Suite

	logs *observer.ObservedLogs
	log  *zap.Logger
}

func TestAccessLogSuite(t *testing.T) {
	suite.Run(t, new(AccessLogSuite))
}

func (s *AccessLogSuite) SetupTest() {
	core, logs := observer.New(zapcore.DebugLevel)
	s.logs, s.log = logs, zap.New(core)
}

func (s *AccessLogSuite) serve(h http.Handler, req *http.Request) {
	accessLog(s.log, "public", h).ServeHTTP(httptest.NewRecorder(), req)
}

func (s *AccessLogSuite) only() observer.LoggedEntry {
	entries := s.logs.All()
	s.Require().Len(entries, 1, "exactly one access-log line per request")
	return entries[0]
}

func (s *AccessLogSuite) TestOneStructuredLinePerRequest() {
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Set by the request-id middleware further in, if present.
		w.Header().Set("X-Request-Id", "req-123")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("hello"))
	})
	req := httptest.NewRequest(http.MethodPost, "/token", http.NoBody)
	req.RemoteAddr = "10.1.2.3:4567"
	req.Header.Set("User-Agent", "tempogate-cli/1.0")

	s.serve(h, req)

	e := s.only()
	s.Equal(zapcore.InfoLevel, e.Level)
	s.Equal("http request", e.Message)
	f := e.ContextMap()
	s.Equal("public", f["listener"])
	s.Equal("POST", f["method"])
	s.Equal("/token", f["path"])
	s.EqualValues(http.StatusCreated, f["status"])
	s.EqualValues(5, f["bytes"])
	s.Equal("10.1.2.3:4567", f["remote_addr"])
	s.Equal("tempogate-cli/1.0", f["user_agent"])
	s.Equal("req-123", f["request_id"])
	s.Contains(f, "duration")
}

func (s *AccessLogSuite) TestImplicitStatusIs200() {
	s.serve(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}), httptest.NewRequest(http.MethodGet, "/userinfo", http.NoBody))

	f := s.only().ContextMap()
	s.EqualValues(http.StatusOK, f["status"])
	s.NotContains(f, "request_id", "no request id header, no field")
}

// Query strings carry OAuth codes, states and PKCE verifiers; headers carry
// bearer tokens, client secrets and session cookies; form bodies carry
// refresh tokens. None of it may reach the log.
func (s *AccessLogSuite) TestSecretsAreNeverLogged() {
	const secret = "s3cr3t-value"
	req := httptest.NewRequest(http.MethodPost,
		"/callback/google?code="+secret+"&state="+secret,
		strings.NewReader("grant_type=refresh_token&refresh_token="+secret))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+secret)
	req.AddCookie(&http.Cookie{Name: "tg_session", Value: secret})

	s.serve(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.WriteHeader(http.StatusFound)
	}), req)

	f := s.only().ContextMap()
	s.Equal("/callback/google", f["path"])
	rendered := fmt.Sprint(f)
	s.NotContains(rendered, secret)
	s.NotContains(rendered, "code=")
}

// Kubelet probes and Prometheus scrapes arrive every few seconds per pod and
// would drown the real traffic, so they log at debug.
func (s *AccessLogSuite) TestProbeAndScrapePathsLogAtDebug() {
	ok := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	for _, path := range []string{"/healthz", "/readyz", "/admin/healthz", "/metrics"} {
		s.Run(path, func() {
			s.SetupTest()
			s.serve(ok, httptest.NewRequest(http.MethodGet, path, http.NoBody))
			s.Equal(zapcore.DebugLevel, s.only().Level)
		})
	}
}

// Below the logger's level nothing is built or written: probe and scrape
// lines cost nothing at the default info level.
func (s *AccessLogSuite) TestProbeLinesDroppedAtInfo() {
	core, logs := observer.New(zapcore.InfoLevel)
	accessLog(zap.New(core), "public", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).
		ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/readyz", http.NoBody))

	s.Zero(logs.Len())
}

// The wrapper must not hide optional interfaces from handlers further in
// (http.ResponseController reaches them through Unwrap).
func (s *AccessLogSuite) TestResponseControllerStillWorks() {
	var flushErr error
	s.serve(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		flushErr = http.NewResponseController(w).Flush()
	}), httptest.NewRequest(http.MethodGet, "/device", http.NoBody))

	s.Require().NoError(flushErr)
}
