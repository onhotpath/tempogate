package oidc

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/onhotpath/tempogate/telemetry"
)

// The scrape of oidc's metrics through the real exporter, line for line: the
// names, HELP text, label order and buckets are a documented contract
// (docs/operations.md) that an exporter or translator upgrade must not move.
func TestExpositionIsUnchanged(t *testing.T) {
	p, err := telemetry.NewProvider(telemetry.WithBuildInfo("v1", "c1"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Shutdown(context.Background()) })
	tm, err := NewTelemetry(p.Meter())
	require.NoError(t, err)

	ctx := context.Background()
	tm.logins.Inc(ctx, loginLabels{loginSuccess, reasonNone})
	tm.logins.Inc(ctx, loginLabels{loginFailure, reasonDomainNotAllowed})
	tm.token(ctx, grantLabelAuthorizationCode, "")
	tm.token(ctx, grantLabelRefreshToken, "invalid_grant")
	tm.familyRevocations.Inc(ctx, revocationLabels{"refresh_token_reuse"})
	tm.authzDenied.Inc(ctx, authzLabels{authzStageLogin})
	tm.rateLimited.Inc(ctx, rateLimitLabels{"token"})
	tm.upstreamDuration.Record(ctx, 0.12, upstreamLabels{"code_exchange"})
	tm.upstreamErrors.Inc(ctx, upstreamErrorLabels{"discovery", upstreamReasonTimeout})

	rec := httptest.NewRecorder()
	p.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", http.NoBody))
	body, err := io.ReadAll(rec.Body)
	require.NoError(t, err)
	var got []string
	for _, line := range strings.Split(string(body), "\n") {
		if strings.Contains(line, "tempogate_") {
			got = append(got, line)
		}
	}
	sort.Strings(got)
	require.Equal(t, strings.Split(strings.TrimSpace(wantExposition), "\n"), got)
}

const wantExposition = `
# HELP tempogate_authz_denied_total Admitted people refused because no authorization rule grants them any Temporal permissions, by stage.
# HELP tempogate_build_info Always 1; labels carry the running build's version and commit.
# HELP tempogate_logins_total Completed Google sign-in callbacks by result (success, failure) and reason.
# HELP tempogate_rate_limited_total Requests rejected with 429 by the per-client rate limiter, by endpoint.
# HELP tempogate_refresh_family_revocations_total Refresh-token families tempogate revoked on its own, by security event.
# HELP tempogate_token_errors_total Failed /token requests by grant type and OAuth2 error code.
# HELP tempogate_tokens_issued_total Tokens minted by /token, by grant type.
# HELP tempogate_upstream_errors_total Failed calls to the upstream IdP (Google), by operation and reason (timeout or error).
# HELP tempogate_upstream_request_duration_seconds Latency of calls to the upstream IdP (Google), by operation.
# TYPE tempogate_authz_denied_total counter
# TYPE tempogate_build_info gauge
# TYPE tempogate_logins_total counter
# TYPE tempogate_rate_limited_total counter
# TYPE tempogate_refresh_family_revocations_total counter
# TYPE tempogate_token_errors_total counter
# TYPE tempogate_tokens_issued_total counter
# TYPE tempogate_upstream_errors_total counter
# TYPE tempogate_upstream_request_duration_seconds histogram
tempogate_authz_denied_total{stage="login"} 1
tempogate_build_info{commit="c1",version="v1"} 1
tempogate_logins_total{reason="domain_not_allowed",result="failure"} 1
tempogate_logins_total{reason="none",result="success"} 1
tempogate_rate_limited_total{endpoint="token"} 1
tempogate_refresh_family_revocations_total{event="refresh_token_reuse"} 1
tempogate_token_errors_total{error="invalid_grant",grant="refresh_token"} 1
tempogate_tokens_issued_total{grant="authorization_code"} 1
tempogate_upstream_errors_total{op="discovery",reason="timeout"} 1
tempogate_upstream_request_duration_seconds_bucket{op="code_exchange",le="+Inf"} 1
tempogate_upstream_request_duration_seconds_bucket{op="code_exchange",le="0.005"} 0
tempogate_upstream_request_duration_seconds_bucket{op="code_exchange",le="0.01"} 0
tempogate_upstream_request_duration_seconds_bucket{op="code_exchange",le="0.025"} 0
tempogate_upstream_request_duration_seconds_bucket{op="code_exchange",le="0.05"} 0
tempogate_upstream_request_duration_seconds_bucket{op="code_exchange",le="0.1"} 0
tempogate_upstream_request_duration_seconds_bucket{op="code_exchange",le="0.25"} 1
tempogate_upstream_request_duration_seconds_bucket{op="code_exchange",le="0.5"} 1
tempogate_upstream_request_duration_seconds_bucket{op="code_exchange",le="1"} 1
tempogate_upstream_request_duration_seconds_bucket{op="code_exchange",le="10"} 1
tempogate_upstream_request_duration_seconds_bucket{op="code_exchange",le="2.5"} 1
tempogate_upstream_request_duration_seconds_bucket{op="code_exchange",le="5"} 1
tempogate_upstream_request_duration_seconds_count{op="code_exchange"} 1
tempogate_upstream_request_duration_seconds_sum{op="code_exchange"} 0.12
`
