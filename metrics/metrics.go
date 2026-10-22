// Package metrics owns tempogate's Prometheus registry and the collectors the
// server exposes on the admin listener's /metrics. Feature packages never
// import Prometheus: each declares a small observer interface of its own
// (oidc.LoginObserver, oidc.TokenObserver, oidc.RateLimitObserver, oidc.AuthzObserver,
// google.Observer, sqlite.ErrorObserver) and *Metrics satisfies them
// structurally, bound via fx.As in Fx. Only the full server build links this
// package; the lean CLI never does.
package metrics

import (
	"errors"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/onhotpath/tempogate/oidc"
)

const namespace = "tempogate"

// Reasons for tempogate_upstream_errors_total.
const (
	upstreamReasonTimeout = "timeout"
	upstreamReasonError   = "error"
)

type options struct {
	version string
	commit  string
}

type Option func(*options)

// WithBuildInfo sets the version and commit labels of tempogate_build_info,
// so dashboards can correlate a behaviour change with a rollout.
func WithBuildInfo(version, commit string) Option {
	return func(o *options) { o.version, o.commit = version, commit }
}

// Metrics is the registry plus every tempogate collector. A private registry
// (not prometheus.DefaultRegisterer) keeps tests isolated and stops a
// transitive dependency from silently adding series to our scrape.
type Metrics struct {
	reg *prometheus.Registry

	logins            *prometheus.CounterVec
	tokensIssued      *prometheus.CounterVec
	tokenErrors       *prometheus.CounterVec
	familyRevocations *prometheus.CounterVec
	authzDenied       *prometheus.CounterVec
	rateLimited       *prometheus.CounterVec
	upstreamDuration  *prometheus.HistogramVec
	upstreamErrors    *prometheus.CounterVec
	dbErrors          *prometheus.CounterVec
}

func New(opts ...Option) *Metrics {
	o := &options{version: "dev", commit: "unknown"}
	for _, opt := range opts {
		opt(o)
	}

	m := &Metrics{
		reg: prometheus.NewRegistry(),
		logins: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "logins_total",
			Help:      "Completed Google sign-in callbacks by result (success, failure) and reason.",
		}, []string{"result", "reason"}),
		tokensIssued: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "tokens_issued_total",
			Help:      "Tokens minted by /token, by grant type.",
		}, []string{"grant"}),
		tokenErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "token_errors_total",
			Help:      "Failed /token requests by grant type and OAuth2 error code.",
		}, []string{"grant", "error"}),
		familyRevocations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "refresh_family_revocations_total",
			Help:      "Refresh-token families tempogate revoked on its own, by security event.",
		}, []string{"event"}),
		authzDenied: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "authz_denied_total",
			Help:      "Admitted people refused because no authorization rule grants them any Temporal permissions, by stage.",
		}, []string{"stage"}),
		rateLimited: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "rate_limited_total",
			Help:      "Requests rejected with 429 by the per-client rate limiter, by endpoint.",
		}, []string{"endpoint"}),
		upstreamDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "upstream_request_duration_seconds",
			Help:      "Latency of calls to the upstream IdP (Google), by operation.",
			Buckets:   prometheus.DefBuckets,
		}, []string{"op"}),
		upstreamErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "upstream_errors_total",
			Help:      "Failed calls to the upstream IdP (Google), by operation and reason (timeout or error).",
		}, []string{"op", "reason"}),
		dbErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "db_errors_total",
			Help:      "State store (SQLite) operations that failed, by operation. Not-found results are not errors.",
		}, []string{"op"}),
	}

	buildInfo := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "build_info",
		Help:      "Always 1; labels carry the running build's version and commit.",
	}, []string{"version", "commit"})
	buildInfo.WithLabelValues(o.version, o.commit).Set(1)

	m.reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		buildInfo,
		m.logins,
		m.tokensIssued,
		m.tokenErrors,
		m.familyRevocations,
		m.authzDenied,
		m.rateLimited,
		m.upstreamDuration,
		m.upstreamErrors,
		m.dbErrors,
	)
	return m
}

// Handler serves the registry in the Prometheus exposition format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}

// ObserveLogin satisfies oidc.LoginObserver.
func (m *Metrics) ObserveLogin(result, reason string) {
	m.logins.WithLabelValues(result, reason).Inc()
}

// ObserveToken satisfies oidc.TokenObserver: an empty errorCode is a minted
// token, anything else is the OAuth2 error the request failed with.
func (m *Metrics) ObserveToken(grant, errorCode string) {
	if errorCode == "" {
		m.tokensIssued.WithLabelValues(grant).Inc()
		return
	}
	m.tokenErrors.WithLabelValues(grant, errorCode).Inc()
}

// ObserveFamilyRevoked satisfies oidc.TokenObserver.
func (m *Metrics) ObserveFamilyRevoked(event string) {
	m.familyRevocations.WithLabelValues(event).Inc()
}

// ObserveAuthzDenied satisfies oidc.AuthzObserver.
func (m *Metrics) ObserveAuthzDenied(stage string) {
	m.authzDenied.WithLabelValues(stage).Inc()
}

// ObserveRateLimited satisfies oidc.RateLimitObserver.
func (m *Metrics) ObserveRateLimited(endpoint string) {
	m.rateLimited.WithLabelValues(endpoint).Inc()
}

// ObserveUpstream satisfies google.Observer. Failed calls are timed too: a
// slow failure is still latency the user waited through. A failure is
// counted as a timeout when the client flagged it as one, so a stalled
// Google is told apart from one that answers with an error.
func (m *Metrics) ObserveUpstream(op string, took time.Duration, err error) {
	m.upstreamDuration.WithLabelValues(op).Observe(took.Seconds())
	if err == nil {
		return
	}
	reason := upstreamReasonError
	var ue *oidc.UpstreamError
	if errors.As(err, &ue) && ue.Timeout {
		reason = upstreamReasonTimeout
	}
	m.upstreamErrors.WithLabelValues(op, reason).Inc()
}

// ObserveDBError satisfies sqlite.ErrorObserver.
func (m *Metrics) ObserveDBError(op string) {
	m.dbErrors.WithLabelValues(op).Inc()
}
