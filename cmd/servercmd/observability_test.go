package servercmd

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/onhotpath/tempogate/admin"
	"github.com/onhotpath/tempogate/api"
)

type ObservabilitySuite struct {
	suite.Suite
}

func TestObservabilitySuite(t *testing.T) {
	suite.Run(t, new(ObservabilitySuite))
}

// params wires the admin surface as api.Fx does in production: the admin
// guard with no token digests and the loopback-only Host allowlist, plus the
// metrics handler.
func (s *ObservabilitySuite) params(logger *zap.Logger, logRequests bool) serveParams {
	metrics := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "tempogate_build_info 1\n")
	})
	guard := admin.NewGuard(admin.WithAllowedHosts([]string{"127.0.0.1:8081"}))
	return serveParams{
		Policy: testPolicy,
		Logger: logger,
		Servers: api.New(api.NewReadiness(),
			api.WithAdminMiddleware(guard.Install),
			api.WithAdminRegistrar(func(a huma.API) {
				huma.Get(a, "/admin/keys", func(context.Context, *struct{}) (*struct{}, error) { return nil, nil })
			}),
			api.WithAdminHandler("GET /metrics", metrics),
		),
		LogRequests: logRequests,
	}
}

func get(h http.Handler, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, http.NoBody))
	return rec
}

// /metrics is an operator surface: reachable on the private admin listener
// only, never on the public one that faces the internet.
func (s *ObservabilitySuite) TestMetricsServedOnAdminListenerOnly() {
	public, adminSrv := httpServers(s.params(zap.NewNop(), false))

	rec := get(adminSrv.Handler, "/metrics")
	s.Equal(http.StatusOK, rec.Code)
	s.Contains(rec.Body.String(), "tempogate_build_info")

	s.Equal(http.StatusNotFound, get(public.Handler, "/metrics").Code)
}

// A scraper presents neither the admin token nor an allowlisted Host
// (Prometheus addresses the pod IP), so /metrics sits outside the admin
// guard while every /admin/* route stays behind it. It still carries the
// listener-wide security headers.
func (s *ObservabilitySuite) TestMetricsBypassesAdminGuardOnly() {
	_, adminSrv := httpServers(s.params(zap.NewNop(), false))
	scrape := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, http.NoBody)
		req.Host = "10.0.0.7:8081"
		rec := httptest.NewRecorder()
		adminSrv.Handler.ServeHTTP(rec, req)
		return rec
	}

	rec := scrape("/metrics")
	s.Equal(http.StatusOK, rec.Code)
	s.Equal("DENY", rec.Header().Get("X-Frame-Options"))
	s.Equal("nosniff", rec.Header().Get("X-Content-Type-Options"))

	s.Equal(http.StatusMisdirectedRequest, scrape("/admin/keys").Code, "the guard still covers /admin/*")
}

func (s *ObservabilitySuite) TestRequestsLoggedOnBothListeners() {
	core, logs := observer.New(zapcore.DebugLevel)
	public, adminSrv := httpServers(s.params(zap.New(core), true))

	get(public.Handler, "/.well-known/openid-configuration?x=1")
	get(adminSrv.Handler, "/admin/keys")

	entries := logs.FilterMessage("http request").All()
	s.Require().Len(entries, 2)
	s.Equal("public", entries[0].ContextMap()["listener"])
	s.Equal("/.well-known/openid-configuration", entries[0].ContextMap()["path"])
	s.Equal("admin", entries[1].ContextMap()["listener"])
}

func (s *ObservabilitySuite) TestRequestLoggingCanBeDisabled() {
	core, logs := observer.New(zapcore.DebugLevel)
	public, adminSrv := httpServers(s.params(zap.New(core), false))

	get(public.Handler, "/healthz")
	get(adminSrv.Handler, "/admin/healthz")

	s.Zero(logs.FilterMessage("http request").Len())
}
