package metrics

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/suite"
	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"

	"github.com/onhotpath/tempogate/oidc"
	"github.com/onhotpath/tempogate/oidc/google"
	"github.com/onhotpath/tempogate/state/sqlite"
)

type MetricsSuite struct {
	suite.Suite

	m *Metrics
}

func TestMetricsSuite(t *testing.T) {
	suite.Run(t, new(MetricsSuite))
}

func (s *MetricsSuite) SetupTest() {
	s.m = New(WithBuildInfo("v1.2.3", "abc1234"))
}

func (s *MetricsSuite) TestLoginsCountedByResultAndReason() {
	s.m.ObserveLogin("success", "none")
	s.m.ObserveLogin("success", "none")
	s.m.ObserveLogin("failure", "domain_not_allowed")

	s.InDelta(2, testutil.ToFloat64(s.m.logins.WithLabelValues("success", "none")), 0)
	s.InDelta(1, testutil.ToFloat64(s.m.logins.WithLabelValues("failure", "domain_not_allowed")), 0)
}

func (s *MetricsSuite) TestTokensCountedByGrantAndErrorsByCode() {
	for _, grant := range []string{"authorization_code", "refresh_token", "device_code"} {
		s.m.ObserveToken(grant, "")
	}
	s.m.ObserveToken("refresh_token", "invalid_grant")

	for _, grant := range []string{"authorization_code", "refresh_token", "device_code"} {
		s.InDelta(1, testutil.ToFloat64(s.m.tokensIssued.WithLabelValues(grant)), 0, grant)
	}
	s.InDelta(1, testutil.ToFloat64(s.m.tokenErrors.WithLabelValues("refresh_token", "invalid_grant")), 0)
	// A failed exchange must not also count as an issued token.
	s.InDelta(1, testutil.ToFloat64(s.m.tokensIssued.WithLabelValues("refresh_token")), 0)
}

func (s *MetricsSuite) TestFamilyRevocationsCountedByEvent() {
	s.m.ObserveFamilyRevoked("refresh_token_reuse")
	s.m.ObserveFamilyRevoked("refresh_domain_not_allowed")
	s.m.ObserveFamilyRevoked("refresh_token_reuse")

	s.InDelta(2, testutil.ToFloat64(s.m.familyRevocations.WithLabelValues("refresh_token_reuse")), 0)
	s.InDelta(1, testutil.ToFloat64(s.m.familyRevocations.WithLabelValues("refresh_domain_not_allowed")), 0)
}

func (s *MetricsSuite) TestRateLimitedCountedByEndpoint() {
	s.m.ObserveRateLimited("token")
	s.m.ObserveRateLimited("token")
	s.m.ObserveRateLimited("authorize")

	s.InDelta(2, testutil.ToFloat64(s.m.rateLimited.WithLabelValues("token")), 0)
	s.InDelta(1, testutil.ToFloat64(s.m.rateLimited.WithLabelValues("authorize")), 0)
}

func (s *MetricsSuite) TestUpstreamLatencyAndErrors() {
	s.m.ObserveUpstream("code_exchange", 120*time.Millisecond, nil)
	s.m.ObserveUpstream("code_exchange", 80*time.Millisecond, errors.New("boom"))

	s.Equal(1, testutil.CollectAndCount(s.m.upstreamDuration, "tempogate_upstream_request_duration_seconds"))
	s.InDelta(1, testutil.ToFloat64(s.m.upstreamErrors.WithLabelValues("code_exchange")), 0)
	s.Contains(s.scrape(), `tempogate_upstream_request_duration_seconds_count{op="code_exchange"} 2`)
}

func (s *MetricsSuite) TestDBErrorsCountedByOp() {
	s.m.ObserveDBError("consume_refresh")
	s.m.ObserveDBError("consume_refresh")

	s.InDelta(2, testutil.ToFloat64(s.m.dbErrors.WithLabelValues("consume_refresh")), 0)
}

func (s *MetricsSuite) TestHandlerExposesRuntimeAndBuildInfo() {
	body := s.scrape()

	s.Contains(body, `tempogate_build_info{commit="abc1234",version="v1.2.3"} 1`)
	s.Contains(body, "go_goroutines")
	s.Contains(body, "process_start_time_seconds")
}

// Label values must come from fixed sets: emails, tokens, client secrets or
// raw request input would explode the series count and leak secrets into
// the TSDB. The only free-form inputs are op/reason/grant strings chosen by
// tempogate's own code, so the exposed label names are pinned here.
func (s *MetricsSuite) TestLabelNamesAreLowCardinality() {
	s.m.ObserveLogin("failure", "upstream_error")
	s.m.ObserveToken("authorization_code", "invalid_grant")
	s.m.ObserveUpstream("verify_id_token", time.Millisecond, errors.New("x"))
	s.m.ObserveDBError("save_refresh")
	s.m.ObserveFamilyRevoked("auth_code_reuse")
	s.m.ObserveRateLimited("device_authorization")

	allowed := map[string]bool{
		"result": true, "reason": true, "grant": true, "error": true, "op": true,
		"event": true, "endpoint": true, "le": true, "version": true, "commit": true,
	}
	for _, line := range strings.Split(s.scrape(), "\n") {
		if !strings.HasPrefix(line, "tempogate_") {
			continue
		}
		open, closing := strings.IndexByte(line, '{'), strings.IndexByte(line, '}')
		if open < 0 {
			continue
		}
		for _, pair := range strings.Split(line[open+1:closing], ",") {
			name, _, _ := strings.Cut(pair, "=")
			s.Truef(allowed[name], "unexpected label %q in %q", name, line)
		}
	}
}

func (s *MetricsSuite) scrape() string {
	rec := httptest.NewRecorder()
	s.m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", http.NoBody))
	s.Equal(http.StatusOK, rec.Code)
	b, err := io.ReadAll(rec.Body)
	s.Require().NoError(err)
	return string(b)
}

// The fx module hands every consumer the same registry and the handler that
// exposes it.
func TestFxProvidesObserversAndHandler(t *testing.T) {
	var (
		logins  oidc.LoginObserver
		tokens  oidc.TokenObserver
		limits  oidc.RateLimitObserver
		up      google.Observer
		db      sqlite.ErrorObserver
		handler http.Handler
	)
	app := fxtest.New(t,
		Fx(),
		fx.Invoke(func(l oidc.LoginObserver, tk oidc.TokenObserver, rl oidc.RateLimitObserver, u google.Observer, d sqlite.ErrorObserver, p struct {
			fx.In
			H http.Handler `name:"metrics_handler"`
		}) {
			logins, tokens, limits, up, db, handler = l, tk, rl, u, d, p.H
		}),
	)
	app.RequireStart().RequireStop()

	logins.ObserveLogin("success", "none")
	tokens.ObserveToken("refresh_token", "")
	tokens.ObserveFamilyRevoked("refresh_token_reuse")
	limits.ObserveRateLimited("token")
	up.ObserveUpstream("discovery", time.Millisecond, nil)
	db.ObserveDBError("probe")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", http.NoBody))
	body := rec.Body.String()
	for _, want := range []string{
		`tempogate_logins_total{reason="none",result="success"} 1`,
		`tempogate_tokens_issued_total{grant="refresh_token"} 1`,
		`tempogate_refresh_family_revocations_total{event="refresh_token_reuse"} 1`,
		`tempogate_rate_limited_total{endpoint="token"} 1`,
		`tempogate_upstream_request_duration_seconds_count{op="discovery"} 1`,
		`tempogate_db_errors_total{op="probe"} 1`,
		`tempogate_build_info{commit="unknown",version="dev"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape is missing %q", want)
		}
	}
}
