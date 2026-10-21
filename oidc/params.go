package oidc

import (
	"fmt"
	"net/http"
)

// Length caps on client-supplied request parameters. /authorize and
// /device_authorization store several of these verbatim in a row per
// anonymous request, so without a bound one caller could write about a
// megabyte per request and fill the state volume. The caps sit well above
// anything a real client sends.
const (
	maxClientIDLen    = 256
	maxRedirectURILen = 2048
	maxScopeLen       = 1024
	maxStateLen       = 512
	maxNonceLen       = 512

	// maxCredentialLen bounds the opaque values /token hashes and looks up
	// (codes, refresh tokens, PKCE verifiers). tempogate issues 43-character
	// values; this is a generous ceiling, not a format check.
	maxCredentialLen = 1024

	// pkceChallengeLen is the length of an S256 code_challenge: the
	// unpadded base64url of a SHA-256 digest (RFC 7636 §4.2).
	pkceChallengeLen = 43
)

type paramCap struct {
	name  string
	value string
	max   int
}

// checkParamLengths rejects the first parameter over its cap with an RFC
// 6749 invalid_request, before anything is persisted.
func checkParamLengths(caps ...paramCap) error {
	for _, c := range caps {
		if len(c.value) > c.max {
			return oauthErr(http.StatusBadRequest, "invalid_request",
				fmt.Sprintf("%s exceeds %d bytes", c.name, c.max))
		}
	}
	return nil
}

// validCodeChallenge reports whether v has the exact shape of an S256
// challenge, so a malformed one is refused at /authorize rather than
// stored and failed at /token.
func validCodeChallenge(v string) bool {
	if len(v) != pkceChallengeLen {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return false
		}
	}
	return true
}
