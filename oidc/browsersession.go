package oidc

import (
	"errors"
	"time"
)

// ErrBrowserSessionNotFound is returned by LookupBrowserSession when no row
// matches — because the sid was never minted, was already deleted, or its
// row was reaped. SessionManager.Get maps this to ErrNoSession so the
// verification UI restarts the upstream IdP round-trip; the store itself
// stays uniform with the other consumer-side sentinels (ErrAuthCodeNotFound,
// ErrRefreshNotFound).
var ErrBrowserSessionNotFound = errors.New("oidc: browser session not found")

// BrowserSession is the first-party session row indexed by the signed
// HttpOnly cookie that the device-flow verification page sets after the user
// completes the upstream IdP round-trip. SID is the opaque 32-byte random
// identifier (base64url) the cookie carries; Subject and Email are the
// authenticated identity bound to it; ExpiresAt is the absolute upper bound on session
// lifetime. TTL enforcement is the handler's concern — the store will hand
// back an expired row without complaint, mirroring AuthCode / Refresh.
type BrowserSession struct {
	SID       string
	Subject   string
	Email     string
	CreatedAt time.Time
	ExpiresAt time.Time
}
