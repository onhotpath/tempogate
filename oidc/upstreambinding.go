package oidc

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

const (
	upstreamCookieBase = "tempogate_upstream_"
	hostCookiePrefix   = "__Host-"

	// upstreamCookieIDHexLen is how much of SHA-256(state) names the cookie:
	// enough that two logins running in one browser never collide.
	upstreamCookieIDHexLen = 16

	// Domain-separation labels for the values derived from one key. The NUL
	// keeps a label from running into the state, and no other MAC under
	// OIDC_SESSION_SIGNING_KEY (session sid, device bounce state) contains
	// one.
	labelUpstreamVerifier = "tempogate/upstream/pkce-verifier\x00"
	labelUpstreamNonce    = "tempogate/upstream/nonce\x00"
	labelUpstreamBinding  = "tempogate/upstream/browser-binding\x00"
)

// UpstreamBinding protects the Google leg of the flow. For each internal
// state it derives three values under the server's signing key: the PKCE
// code_verifier sent (as its S256 challenge) to Google, the OIDC nonce Google
// must echo in the id_token, and the value of a cookie that binds the state
// to the browser that called /authorize. /callback/google refuses a state
// presented without that cookie, so an attacker cannot complete their own
// Google login in a victim's browser (login CSRF), and PKCE + nonce stop a
// code or id_token from another login being injected into this one.
//
// Deriving instead of storing keeps all three server-side without widening
// the auth_requests row: they are recomputed from the state, never persisted,
// and only the challenge, the nonce and an HttpOnly cookie ever leave
// tempogate. Rotating the key invalidates logins in flight, which the
// five-minute auth request TTL already bounds.
type UpstreamBinding struct {
	key        []byte
	secure     bool
	cookiePath string
	namePrefix string
}

// NewUpstreamBinding builds the binding for issuer under key (the decoded
// OIDC_SESSION_SIGNING_KEY). Over https the cookie is `__Host-` prefixed,
// which browsers accept only with Secure, no Domain and Path=/, so a sibling
// subdomain cannot plant one. A browser refuses both over plain http, so a
// plain-http issuer (local, compose) gets an unprefixed, non-Secure cookie
// scoped to the callback path instead.
func NewUpstreamBinding(issuer string, key []byte) (*UpstreamBinding, error) {
	if len(key) != sessionSigningKeyBytes {
		return nil, fmt.Errorf("oidc: upstream binding key must be %d bytes, got %d", sessionSigningKeyBytes, len(key))
	}
	b := &UpstreamBinding{
		key:        key,
		secure:     true,
		cookiePath: "/",
		namePrefix: hostCookiePrefix + upstreamCookieBase,
	}
	// An unparseable issuer keeps the strict https shape: failing closed
	// means the cookie is never sent, not that it is sent insecurely.
	if u, err := url.Parse(strings.TrimSpace(issuer)); err == nil && strings.EqualFold(u.Scheme, "http") {
		b.secure = false
		b.cookiePath = strings.TrimRight(u.Path, "/") + CallbackPath
		b.namePrefix = upstreamCookieBase
	}
	return b, nil
}

// Cookie is the binding cookie /authorize sets for internalState. It lives
// exactly as long as the auth request. SameSite=Lax still lets it ride the
// top-level redirect back from Google.
func (b *UpstreamBinding) Cookie(internalState string) *http.Cookie {
	return b.cookie(internalState, b.derive(labelUpstreamBinding, internalState), int(authRequestTTL.Seconds()))
}

// clearCookie drops the binding cookie once the state has been used.
func (b *UpstreamBinding) clearCookie(internalState string) *http.Cookie {
	return b.cookie(internalState, "", -1)
}

func (b *UpstreamBinding) cookie(internalState, value string, maxAge int) *http.Cookie {
	return &http.Cookie{ //nolint:gosec // G124: Secure is off only for a plain-http issuer, where a browser would drop a Secure cookie
		Name:     b.cookieName(internalState),
		Value:    value,
		Path:     b.cookiePath,
		HttpOnly: true,
		Secure:   b.secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	}
}

// boundToBrowser reports whether the request's cookies carry the binding for
// internalState. The cookie is named per state so concurrent logins in one
// browser (two tabs, or a device approval alongside a Web UI login) do not
// overwrite each other.
func (b *UpstreamBinding) boundToBrowser(cookieHeader, internalState string) bool {
	c, err := requestFromCookieHeader(cookieHeader).Cookie(b.cookieName(internalState))
	if err != nil {
		return false
	}
	want := b.derive(labelUpstreamBinding, internalState)
	return subtle.ConstantTimeCompare([]byte(c.Value), []byte(want)) == 1
}

// codeVerifier is the RFC 7636 verifier for internalState: 43 base64url
// characters, the minimum length and 256 bits of entropy.
func (b *UpstreamBinding) codeVerifier(internalState string) string {
	return b.derive(labelUpstreamVerifier, internalState)
}

// codeChallenge is the S256 challenge of codeVerifier.
func (b *UpstreamBinding) codeChallenge(internalState string) string {
	sum := sha256.Sum256([]byte(b.codeVerifier(internalState)))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (b *UpstreamBinding) nonce(internalState string) string {
	return b.derive(labelUpstreamNonce, internalState)
}

func (b *UpstreamBinding) cookieName(internalState string) string {
	sum := sha256.Sum256([]byte(internalState))
	return b.namePrefix + hex.EncodeToString(sum[:])[:upstreamCookieIDHexLen]
}

func (b *UpstreamBinding) derive(label, internalState string) string {
	mac := hmac.New(sha256.New, b.key)
	mac.Write([]byte(label))
	mac.Write([]byte(internalState))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
