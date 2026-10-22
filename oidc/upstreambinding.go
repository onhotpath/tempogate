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
	labelUpstreamVerifier  = "tempogate/upstream/pkce-verifier\x00"
	labelUpstreamNonce     = "tempogate/upstream/nonce\x00"
	labelUpstreamRequestID = "tempogate/upstream/request-id\x00"
	labelUpstreamBinding   = "tempogate/upstream/browser-binding\x00"
)

// UpstreamBinding protects the upstream leg of the flow. For each
// (connector, internal state) it derives, under the server's signing key, the
// PKCE code_verifier sent (as its S256 challenge) upstream, the nonce the
// upstream must echo, a request id for protocols that echo one, and the value
// of a cookie that binds the state to the browser that called /authorize.
// The callback refuses a state presented without that cookie, so an attacker
// cannot complete their own upstream login in a victim's browser (login
// CSRF), and PKCE + nonce stop a code or id_token from another login being
// injected into this one. The connector id is part of every derivation, so a
// state minted for one connector never verifies at another's callback.
//
// Deriving instead of storing keeps all of them server-side without widening
// the auth_requests row: they are recomputed from the state, never persisted,
// and only the challenge, the nonce, the request id and an HttpOnly cookie
// ever leave tempogate. Rotating the key invalidates logins in flight, which
// the five-minute auth request TTL already bounds.
type UpstreamBinding struct {
	key        []byte
	secure     bool
	issuerPath string
	namePrefix string
}

// NewUpstreamBinding builds the binding for issuer under key (the decoded
// OIDC_SESSION_SIGNING_KEY). Over https the cookie is `__Host-` prefixed,
// which browsers accept only with Secure, no Domain and Path=/, so a sibling
// subdomain cannot plant one. A browser refuses both over plain http, so a
// plain-http issuer (local, compose) gets an unprefixed, non-Secure cookie
// scoped to the connector's callback path instead.
func NewUpstreamBinding(issuer string, key []byte) (*UpstreamBinding, error) {
	if len(key) != sessionSigningKeyBytes {
		return nil, fmt.Errorf("oidc: upstream binding key must be %d bytes, got %d", sessionSigningKeyBytes, len(key))
	}
	b := &UpstreamBinding{
		key:        key,
		secure:     true,
		namePrefix: hostCookiePrefix + upstreamCookieBase,
	}
	// An unparseable issuer keeps the strict https shape: failing closed
	// means the cookie is never sent, not that it is sent insecurely.
	if u, err := url.Parse(strings.TrimSpace(issuer)); err == nil && strings.EqualFold(u.Scheme, "http") {
		b.secure = false
		b.issuerPath = strings.TrimRight(u.Path, "/")
		b.namePrefix = upstreamCookieBase
	}
	return b, nil
}

// Cookie is the binding cookie /authorize sets for internalState on its way
// to connectorID. It lives exactly as long as the auth request. SameSite=Lax
// still lets it ride the top-level redirect back from the upstream.
func (b *UpstreamBinding) Cookie(connectorID, internalState string) *http.Cookie {
	return b.cookie(connectorID, internalState, b.derive(labelUpstreamBinding, connectorID, internalState), int(authRequestTTL.Seconds()))
}

// clearCookie drops the binding cookie once the state has been used.
func (b *UpstreamBinding) clearCookie(connectorID, internalState string) *http.Cookie {
	return b.cookie(connectorID, internalState, "", -1)
}

func (b *UpstreamBinding) cookie(connectorID, internalState, value string, maxAge int) *http.Cookie {
	path := "/"
	if !b.secure {
		path = b.issuerPath + CallbackPath(connectorID)
	}
	return &http.Cookie{ //nolint:gosec // G124: Secure is off only for a plain-http issuer, where a browser would drop a Secure cookie
		Name:     b.cookieName(internalState),
		Value:    value,
		Path:     path,
		HttpOnly: true,
		Secure:   b.secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	}
}

// boundToBrowser reports whether the request's cookies carry the binding for
// internalState at connectorID. The cookie is named per state so concurrent
// logins in one browser (two tabs, or a device approval alongside a Web UI
// login) do not overwrite each other.
func (b *UpstreamBinding) boundToBrowser(cookieHeader, connectorID, internalState string) bool {
	c, err := requestFromCookieHeader(cookieHeader).Cookie(b.cookieName(internalState))
	if err != nil {
		return false
	}
	want := b.derive(labelUpstreamBinding, connectorID, internalState)
	return subtle.ConstantTimeCompare([]byte(c.Value), []byte(want)) == 1
}

// codeVerifier is the RFC 7636 verifier for internalState: 43 base64url
// characters, the minimum length and 256 bits of entropy.
func (b *UpstreamBinding) codeVerifier(connectorID, internalState string) string {
	return b.derive(labelUpstreamVerifier, connectorID, internalState)
}

// codeChallenge is the S256 challenge of codeVerifier.
func (b *UpstreamBinding) codeChallenge(connectorID, internalState string) string {
	sum := sha256.Sum256([]byte(b.codeVerifier(connectorID, internalState)))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (b *UpstreamBinding) nonce(connectorID, internalState string) string {
	return b.derive(labelUpstreamNonce, connectorID, internalState)
}

// requestID is an XML NCName (it may not start with a digit), so it can be
// a SAML AuthnRequest ID as it is.
func (b *UpstreamBinding) requestID(connectorID, internalState string) string {
	mac := b.mac(labelUpstreamRequestID, connectorID, internalState)
	return "_" + hex.EncodeToString(mac)
}

func (b *UpstreamBinding) cookieName(internalState string) string {
	sum := sha256.Sum256([]byte(internalState))
	return b.namePrefix + hex.EncodeToString(sum[:])[:upstreamCookieIDHexLen]
}

func (b *UpstreamBinding) derive(label, connectorID, internalState string) string {
	return base64.RawURLEncoding.EncodeToString(b.mac(label, connectorID, internalState))
}

// mac keys every value on the connector id as well as the state. A
// connector id never contains NUL (ValidateConnectorID), so the separator
// keeps (id, state) pairs from running into each other.
func (b *UpstreamBinding) mac(label, connectorID, internalState string) []byte {
	m := hmac.New(sha256.New, b.key)
	m.Write([]byte(label))
	m.Write([]byte(connectorID))
	m.Write([]byte{0})
	m.Write([]byte(internalState))
	return m.Sum(nil)
}
