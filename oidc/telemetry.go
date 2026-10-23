package oidc

import (
	"context"
	"errors"
	"time"

	"github.com/onhotpath/tempogate/observe"
)

// Telemetry is everything oidc and its connectors record: sign-in outcomes,
// /token outcomes, refresh-family revocations, authorization refusals,
// rate-limited requests and upstream calls. Every label value comes from a
// fixed set below (never an email, a client ID, a token or raw request
// input). The zero value records nothing.
type Telemetry struct {
	logins            observe.Counter[loginLabels]
	tokensIssued      observe.Counter[grantLabels]
	tokenErrors       observe.Counter[tokenErrorLabels]
	familyRevocations observe.Counter[revocationLabels]
	authzDenied       observe.Counter[authzLabels]
	rateLimited       observe.Counter[rateLimitLabels]
	upstreamDuration  observe.Histogram[upstreamLabels]
	upstreamErrors    observe.Counter[upstreamErrorLabels]
}

// upstreamBuckets are the upstream latency histogram's bounds in seconds:
// Prometheus' DefBuckets, which the histogram has always had.
var upstreamBuckets = []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10}

// NewTelemetry declares oidc's instruments on m. A nil m records nothing.
func NewTelemetry(m observe.Meter) (*Telemetry, error) {
	var (
		t    Telemetry
		err  error
		errs []error
	)
	t.logins, err = observe.NewCounter[loginLabels](m, "tempogate.logins",
		observe.WithDescription("Completed Google sign-in callbacks by result (success, failure) and reason."))
	errs = append(errs, err)
	t.tokensIssued, err = observe.NewCounter[grantLabels](m, "tempogate.tokens_issued",
		observe.WithDescription("Tokens minted by /token, by grant type."))
	errs = append(errs, err)
	t.tokenErrors, err = observe.NewCounter[tokenErrorLabels](m, "tempogate.token_errors",
		observe.WithDescription("Failed /token requests by grant type and OAuth2 error code."))
	errs = append(errs, err)
	t.familyRevocations, err = observe.NewCounter[revocationLabels](m, "tempogate.refresh_family_revocations",
		observe.WithDescription("Refresh-token families tempogate revoked on its own, by security event."))
	errs = append(errs, err)
	t.authzDenied, err = observe.NewCounter[authzLabels](m, "tempogate.authz_denied",
		observe.WithDescription("Admitted people refused because no authorization rule grants them any Temporal permissions, by stage."))
	errs = append(errs, err)
	t.rateLimited, err = observe.NewCounter[rateLimitLabels](m, "tempogate.rate_limited",
		observe.WithDescription("Requests rejected with 429 by the per-client rate limiter, by endpoint."))
	errs = append(errs, err)
	t.upstreamDuration, err = observe.NewHistogram[upstreamLabels](m, "tempogate.upstream_request.duration",
		observe.WithDescription("Latency of calls to the upstream IdP (Google), by operation."),
		observe.WithUnit("s"),
		observe.WithBuckets(upstreamBuckets...))
	errs = append(errs, err)
	t.upstreamErrors, err = observe.NewCounter[upstreamErrorLabels](m, "tempogate.upstream_errors",
		observe.WithDescription("Failed calls to the upstream IdP (Google), by operation and reason (timeout or error)."))
	errs = append(errs, err)
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return &t, nil
}

// StartUpstream times one call a connector makes upstream, by operation
// ("discovery", "code_exchange", "verify_id_token"); the returned func ends
// it with the call's error, nil on success. A failure is counted as a
// timeout when it is an *UpstreamError flagged as one, so a stalled upstream
// is told apart from one that answers with an error. Failed calls are timed
// too: a slow failure is still latency the user waited through.
func (t *Telemetry) StartUpstream(ctx context.Context, op string) func(err error) {
	start := time.Now()
	return func(err error) {
		t.upstreamDuration.Record(ctx, time.Since(start).Seconds(), upstreamLabels{op: op})
		if err == nil {
			return
		}
		reason := upstreamReasonError
		var ue *UpstreamError
		if errors.As(err, &ue) && ue.Timeout {
			reason = upstreamReasonTimeout
		}
		t.upstreamErrors.Inc(ctx, upstreamErrorLabels{op: op, reason: reason})
	}
}

// token records the outcome of one /token request: an empty errorCode is a
// minted token, anything else the OAuth2 error it failed with.
func (t *Telemetry) token(ctx context.Context, grant, errorCode string) {
	if errorCode == "" {
		t.tokensIssued.Inc(ctx, grantLabels{grant: grant})
		return
	}
	t.tokenErrors.Inc(ctx, tokenErrorLabels{grant: grant, errorCode: errorCode})
}

// loginLabels: result is loginSuccess or loginFailure, reason one of the
// reason* constants.
type loginLabels struct{ result, reason string }

func (l loginLabels) Attrs() []observe.Attr {
	return []observe.Attr{observe.String("result", l.result), observe.String("reason", l.reason)}
}

// grantLabels: grant is one of the grantLabel* constants, never the raw,
// attacker-controlled grant_type.
type grantLabels struct{ grant string }

func (l grantLabels) Attrs() []observe.Attr {
	return []observe.Attr{observe.String("grant", l.grant)}
}

type tokenErrorLabels struct{ grant, errorCode string }

func (l tokenErrorLabels) Attrs() []observe.Attr {
	return []observe.Attr{observe.String("grant", l.grant), observe.String("error", l.errorCode)}
}

// revocationLabels: event is the security event that revoked a family:
// auth_code_reuse, refresh_token_reuse, refresh_domain_not_allowed or
// refresh_authz_denied.
type revocationLabels struct{ event string }

func (l revocationLabels) Attrs() []observe.Attr {
	return []observe.Attr{observe.String("event", l.event)}
}

// authzLabels: stage is one of the authzStage* constants or a grantLabel*.
type authzLabels struct{ stage string }

func (l authzLabels) Attrs() []observe.Attr {
	return []observe.Attr{observe.String("stage", l.stage)}
}

// rateLimitLabels: endpoint is the throttled endpoint (authorize,
// device_authorization, device_verification, token). Never the client
// address: it would be an unbounded label.
type rateLimitLabels struct{ endpoint string }

func (l rateLimitLabels) Attrs() []observe.Attr {
	return []observe.Attr{observe.String("endpoint", l.endpoint)}
}

type upstreamLabels struct{ op string }

func (l upstreamLabels) Attrs() []observe.Attr {
	return []observe.Attr{observe.String("op", l.op)}
}

type upstreamErrorLabels struct{ op, reason string }

func (l upstreamErrorLabels) Attrs() []observe.Attr {
	return []observe.Attr{observe.String("op", l.op), observe.String("reason", l.reason)}
}

const (
	upstreamReasonTimeout = "timeout"
	upstreamReasonError   = "error"
)

const (
	loginSuccess = "success"
	loginFailure = "failure"

	reasonNone                   = "none"
	reasonMissingState           = "missing_state"
	reasonStateNotBound          = "state_not_bound"
	reasonUnknownState           = "unknown_state"
	reasonExpiredRequest         = "expired_request"
	reasonConnectorMismatch      = "connector_mismatch"
	reasonUpstreamDenied         = "upstream_denied"
	reasonMissingCode            = "missing_code"
	reasonUpstreamError          = "upstream_error"
	reasonEmailUnverified        = "email_unverified"
	reasonDomainNotAllowed       = "domain_not_allowed"
	reasonHostedDomainNotAllowed = "hosted_domain_not_allowed"
	reasonAuthzDenied            = "authz_denied"
	reasonInternal               = "internal"

	grantLabelAuthorizationCode = "authorization_code"
	grantLabelRefreshToken      = "refresh_token"
	grantLabelDeviceCode        = "device_code"
	grantLabelOther             = "other"

	// errorCodeServer is reported for failures that are not an OAuth2 error
	// response (store or signer failures surfacing as a 500).
	errorCodeServer = "server_error"
)
