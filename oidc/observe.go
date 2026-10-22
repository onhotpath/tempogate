package oidc

// LoginObserver is told the outcome of every Google sign-in callback. result
// is "success" or "failure"; reason is one of the reason* constants below.
// Both come from fixed sets so a metrics backend can use them as labels.
type LoginObserver interface {
	ObserveLogin(result, reason string)
}

// TokenObserver is told the outcome of every /token request and every
// refresh-token family tempogate revokes on its own. grant is one of the
// short grant names below (never the raw, attacker-controlled grant_type);
// errorCode is the OAuth2 error code, or empty when a token was minted.
// event is the security event that revoked a family: auth_code_reuse,
// refresh_token_reuse or refresh_domain_not_allowed.
type TokenObserver interface {
	ObserveToken(grant, errorCode string)
	ObserveFamilyRevoked(event string)
}

// RateLimitObserver is told every request the rate limiter rejects, by the
// throttled endpoint (authorize, device_authorization, device_verification,
// token). Never the client address: it would be an unbounded label.
type RateLimitObserver interface {
	ObserveRateLimited(endpoint string)
}

const (
	loginSuccess = "success"
	loginFailure = "failure"

	reasonNone                   = "none"
	reasonMissingState           = "missing_state"
	reasonStateNotBound          = "state_not_bound"
	reasonUnknownState           = "unknown_state"
	reasonExpiredRequest         = "expired_request"
	reasonUpstreamDenied         = "upstream_denied"
	reasonMissingCode            = "missing_code"
	reasonUpstreamError          = "upstream_error"
	reasonEmailUnverified        = "email_unverified"
	reasonDomainNotAllowed       = "domain_not_allowed"
	reasonHostedDomainNotAllowed = "hosted_domain_not_allowed"
	reasonInternal               = "internal"

	grantLabelAuthorizationCode = "authorization_code"
	grantLabelRefreshToken      = "refresh_token"
	grantLabelDeviceCode        = "device_code"
	grantLabelOther             = "other"

	// errorCodeServer is reported for failures that are not an OAuth2 error
	// response (store or signer failures surfacing as a 500).
	errorCodeServer = "server_error"
)

type nopObserver struct{}

func (nopObserver) ObserveLogin(string, string) {}
func (nopObserver) ObserveToken(string, string) {}
func (nopObserver) ObserveFamilyRevoked(string) {}
func (nopObserver) ObserveRateLimited(string)   {}
