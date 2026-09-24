package oidc

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	// DefaultSessionCookieName is the cookie this manager sets and reads. It
	// is exported so handlers, mocks and operator tooling can reference the
	// same string instead of duplicating the literal.
	DefaultSessionCookieName = "tempogate_session"

	// DefaultSessionCookiePath scopes the cookie to the device-flow
	// verification UI. A general-purpose tempogate login is not yet a
	// product surface — narrowing Path keeps a leaked cookie inert outside
	// the one route that consumes it.
	DefaultSessionCookiePath = "/idp/device"

	// defaultSessionTTL is the upper bound on how long a verification-page
	// session may sit between Google round-trip and Approve click. Short
	// enough that an abandoned tab can't be resumed much later — the user
	// simply re-authenticates.
	defaultSessionTTL = 5 * time.Minute

	// sessionSIDEntropyBytes is the size of the opaque sid the cookie
	// carries; 32 bytes (256 bits) makes collision negligible and brute
	// force infeasible.
	sessionSIDEntropyBytes = 32
)

// ErrNoSession is returned by SessionManager.Get when there is no usable
// session for the request — because the cookie was absent, structurally
// invalid, signed with the wrong key, the row was deleted, or the TTL
// elapsed. The verification handler maps this to "bounce through the
// upstream IdP again" so a probe never distinguishes the cases.
var ErrNoSession = errors.New("oidc: no active session")

// BrowserSessionStore is the consumer-side state interface SessionManager
// depends on (see state/doc.go). The concrete *sqlite.Store satisfies it
// structurally; the type is exported only so the composition root can bind
// it via fx.As.
type BrowserSessionStore interface {
	// SaveBrowserSession persists a freshly minted session row. The caller
	// guarantees a unique sid, so a duplicate is a programmer error rather
	// than a runtime surface.
	SaveBrowserSession(ctx context.Context, s BrowserSession) error

	// LookupBrowserSession returns the row for sid, or ErrBrowserSessionNotFound
	// when no row matches. Expiry is the caller's concern — the store does
	// not enforce TTL.
	LookupBrowserSession(ctx context.Context, sid string) (BrowserSession, error)

	// DeleteBrowserSession is best-effort: an unknown sid is a no-op rather
	// than an error, so sign-out and forced-revocation paths can fan out to
	// the store without re-checking existence.
	DeleteBrowserSession(ctx context.Context, sid string) error
}

// SessionManager owns the verification-page session: it mints opaque sids,
// persists them through the BrowserSessionStore, sets the signed cookie on
// the browser, and verifies it back on subsequent requests. The cookie is
// not a JWT — it carries no claims, only the sid + an HMAC over the sid for
// tamper detection. Every lookup is therefore a DB hit, which is cheap at
// the rate the verification UI runs and gives us free revocability.
type SessionManager struct {
	store      BrowserSessionStore
	signingKey []byte

	now    func() time.Time
	newSID func() (string, error)
	ttl    time.Duration
	cookie cookieAttrs
}

type cookieAttrs struct {
	name string
	path string
}

// SessionOption configures a SessionManager at construction. Every seam a
// test might want to control — clock, sid source, ttl, cookie attributes —
// is reachable here so production code can stay on the defaults.
type SessionOption func(*SessionManager)

// WithSessionClock swaps the clock used to stamp CreatedAt / ExpiresAt and
// to compare against ExpiresAt on Get. For tests.
func WithSessionClock(now func() time.Time) SessionOption {
	return func(m *SessionManager) { m.now = now }
}

// WithSessionTTL overrides the default 5-minute session lifetime. Operators
// pick this via OIDC_SESSION_TTL.
func WithSessionTTL(d time.Duration) SessionOption {
	return func(m *SessionManager) { m.ttl = d }
}

// WithSessionSIDGenerator swaps the opaque sid generator. For tests.
func WithSessionSIDGenerator(fn func() (string, error)) SessionOption {
	return func(m *SessionManager) { m.newSID = fn }
}

// WithCookieName overrides the cookie name. Defaults to
// DefaultSessionCookieName; rarely changed outside tests.
func WithCookieName(name string) SessionOption {
	return func(m *SessionManager) { m.cookie.name = name }
}

// WithCookiePath overrides the cookie path. Defaults to
// DefaultSessionCookiePath so the cookie is scoped to the device-flow UI.
func WithCookiePath(path string) SessionOption {
	return func(m *SessionManager) { m.cookie.path = path }
}

// NewSessionManager builds a SessionManager. signingKey is the HMAC-SHA256
// key the cookie's MAC is computed under; callers are expected to sieve a
// length-32 key out of OIDC_SESSION_SIGNING_KEY at config load (failing
// fast on misconfiguration) so this constructor stays unconditional.
func NewSessionManager(store BrowserSessionStore, signingKey []byte, opts ...SessionOption) *SessionManager {
	m := &SessionManager{
		store:      store,
		signingKey: signingKey,
		now:        func() time.Time { return time.Now().UTC() },
		newSID:     randomSID,
		ttl:        defaultSessionTTL,
		cookie: cookieAttrs{
			name: DefaultSessionCookieName,
			path: DefaultSessionCookiePath,
		},
	}
	for _, o := range opts {
		o(m)
	}
	return m
}

// Issue mints a new session for email, persists it, and sets the signed
// cookie on w. The returned sid is the same value embedded in the cookie —
// callers that need to correlate audit logs with the cookie can stash it
// without re-parsing the response.
func (m *SessionManager) Issue(ctx context.Context, w http.ResponseWriter, email string) (string, error) {
	sid, cookie, err := m.IssueCookie(ctx, email)
	if err != nil {
		return "", err
	}
	http.SetCookie(w, cookie)
	return sid, nil
}

// IssueCookie is the writer-free variant of Issue: it mints the session row
// and returns the cookie the caller must add to the response itself. Huma
// typed handlers don't own the raw http.ResponseWriter, so they assemble the
// Set-Cookie header through their typed output struct using this method.
// The two paths cannot drift because Issue is a thin wrapper around it.
func (m *SessionManager) IssueCookie(ctx context.Context, email string) (string, *http.Cookie, error) {
	sid, err := m.newSID()
	if err != nil {
		return "", nil, fmt.Errorf("oidc: generate session sid: %w", err)
	}

	now := m.now()
	bs := BrowserSession{
		SID:       sid,
		Email:     email,
		CreatedAt: now,
		ExpiresAt: now.Add(m.ttl),
	}
	if err := m.store.SaveBrowserSession(ctx, bs); err != nil {
		return "", nil, fmt.Errorf("oidc: persist browser session: %w", err)
	}

	return sid, &http.Cookie{
		Name:     m.cookie.name,
		Value:    m.signCookie(sid),
		Path:     m.cookie.path,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(m.ttl.Seconds()),
	}, nil
}

// Get reads the session cookie off r, verifies its signature, looks up the
// backing row, and enforces TTL against the injected clock. Any of: missing
// cookie, malformed encoding, failed MAC, missing row, expired row collapse
// into ErrNoSession so a probe cannot distinguish them; unexpected store
// errors propagate so they aren't silently swallowed as "no session".
func (m *SessionManager) Get(ctx context.Context, r *http.Request) (BrowserSession, error) {
	sid, ok := m.sidFromRequest(r)
	if !ok {
		return BrowserSession{}, ErrNoSession
	}

	bs, err := m.store.LookupBrowserSession(ctx, sid)
	if errors.Is(err, ErrBrowserSessionNotFound) {
		return BrowserSession{}, ErrNoSession
	}
	if err != nil {
		return BrowserSession{}, fmt.Errorf("oidc: lookup browser session: %w", err)
	}

	if !m.now().Before(bs.ExpiresAt) {
		return BrowserSession{}, ErrNoSession
	}
	return bs, nil
}

// Clear deletes the row indexed by the cookie's sid (best-effort — a missing
// row is fine) and emits a MaxAge=-1 cookie so the browser drops the value
// on receipt. A mangled cookie produces no Delete call (there is nothing to
// target) but still triggers the eviction cookie.
func (m *SessionManager) Clear(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	if sid, ok := m.sidFromRequest(r); ok {
		if err := m.store.DeleteBrowserSession(ctx, sid); err != nil {
			return fmt.Errorf("oidc: delete browser session: %w", err)
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name:     m.cookie.name,
		Value:    "",
		Path:     m.cookie.path,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	return nil
}

// sidFromRequest extracts and verifies the sid from r's cookie. It returns
// (sid, true) on a syntactically valid, MAC-verified cookie and ("", false)
// otherwise, so callers can collapse every failure mode into ErrNoSession
// without leaking which check tripped.
func (m *SessionManager) sidFromRequest(r *http.Request) (string, bool) {
	c, err := r.Cookie(m.cookie.name)
	if err != nil {
		return "", false
	}
	return m.verifyCookie(c.Value)
}

// signCookie produces base64url(sid).base64url(HMAC-SHA256(key, sid)). The
// sid round-trips out of the cookie unchanged so the store lookup uses the
// exact value the row was saved under.
func (m *SessionManager) signCookie(sid string) string {
	mac := hmac.New(sha256.New, m.signingKey)
	mac.Write([]byte(sid))
	return base64.RawURLEncoding.EncodeToString([]byte(sid)) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// verifyCookie checks the format, decodes both halves and verifies the MAC
// in constant time. Any deviation — missing separator, empty half, bad
// base64, wrong MAC — fails the same way, so a remote attacker cannot use
// the response shape to learn which check rejected their forgery.
func (m *SessionManager) verifyCookie(value string) (string, bool) {
	parts := strings.SplitN(value, ".", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", false
	}
	sidBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", false
	}
	gotMAC, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}
	want := hmac.New(sha256.New, m.signingKey)
	want.Write(sidBytes)
	if subtle.ConstantTimeCompare(gotMAC, want.Sum(nil)) != 1 {
		return "", false
	}
	return string(sidBytes), true
}

func randomSID() (string, error) {
	b := make([]byte, sessionSIDEntropyBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
