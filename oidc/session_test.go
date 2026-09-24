package oidc_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	"github.com/onhotpath/tempogate/oidc"
)

const (
	testSessionSID     = "fixed-session-sid"
	testSessionEmail   = "alice@example.com"
	testSessionTTL     = 5 * time.Minute
	testCookieName     = "tempogate_session"
	testCookiePath     = "/idp/device"
	testSigningKeyText = "0123456789abcdef0123456789abcdef"
)

var testSessionNow = time.Unix(1700000000, 0).UTC()

// memBrowserSessionStore satisfies oidc.BrowserSessionStore structurally —
// the consumer-side interface convention means oidc_test owns its own stub.
// Lookup returns oidc.ErrBrowserSessionNotFound for missing rows so the
// SessionManager can map it to oidc.ErrNoSession via errors.Is.
type memBrowserSessionStore struct {
	mu          sync.Mutex
	saved       map[string]oidc.BrowserSession
	saveErr     error
	lookupErr   error
	deleteErr   error
	saveCalls   int
	lookupCalls int
	deleteCalls int
}

func newMemBrowserSessionStore() *memBrowserSessionStore {
	return &memBrowserSessionStore{saved: map[string]oidc.BrowserSession{}}
}

func (m *memBrowserSessionStore) SaveBrowserSession(_ context.Context, bs oidc.BrowserSession) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.saveCalls++
	if m.saveErr != nil {
		return m.saveErr
	}
	m.saved[bs.SID] = bs
	return nil
}

func (m *memBrowserSessionStore) LookupBrowserSession(_ context.Context, sid string) (oidc.BrowserSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lookupCalls++
	if m.lookupErr != nil {
		return oidc.BrowserSession{}, m.lookupErr
	}
	bs, ok := m.saved[sid]
	if !ok {
		return oidc.BrowserSession{}, oidc.ErrBrowserSessionNotFound
	}
	return bs, nil
}

func (m *memBrowserSessionStore) DeleteBrowserSession(_ context.Context, sid string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleteCalls++
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.saved, sid)
	return nil
}

func (m *memBrowserSessionStore) only() oidc.BrowserSession {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, bs := range m.saved {
		return bs
	}
	return oidc.BrowserSession{}
}

func (m *memBrowserSessionStore) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.saved)
}

type SessionSuite struct {
	suite.Suite

	ctx     context.Context
	store   *memBrowserSessionStore
	manager *oidc.SessionManager
	key     []byte
}

func TestSessionSuite(t *testing.T) {
	suite.Run(t, new(SessionSuite))
}

func (s *SessionSuite) SetupTest() {
	s.ctx = context.Background()
	s.store = newMemBrowserSessionStore()
	s.key = []byte(testSigningKeyText)
	s.manager = oidc.NewSessionManager(s.store, s.key,
		oidc.WithSessionClock(func() time.Time { return testSessionNow }),
		oidc.WithSessionTTL(testSessionTTL),
		oidc.WithSessionSIDGenerator(func() (string, error) { return testSessionSID, nil }),
	)
}

func (s *SessionSuite) signedCookie(sid string) string {
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(sid))
	return base64.RawURLEncoding.EncodeToString([]byte(sid)) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (s *SessionSuite) TestIssueSetsCookieAndPersistsRow() {
	rec := httptest.NewRecorder()

	sid, err := s.manager.Issue(s.ctx, rec, testSessionEmail)
	s.Require().NoError(err)
	s.Equal(testSessionSID, sid)

	s.Equal(1, s.store.saveCalls)
	s.Equal(1, s.store.count())
	saved := s.store.only()
	s.Equal(testSessionSID, saved.SID)
	s.Equal(testSessionEmail, saved.Email)
	s.True(saved.CreatedAt.Equal(testSessionNow), "createdAt: want %v, got %v", testSessionNow, saved.CreatedAt)
	s.True(saved.ExpiresAt.Equal(testSessionNow.Add(testSessionTTL)),
		"expiresAt: want %v, got %v", testSessionNow.Add(testSessionTTL), saved.ExpiresAt)

	resp := rec.Result()
	defer resp.Body.Close()
	cookies := resp.Cookies()
	s.Require().Len(cookies, 1)
	c := cookies[0]
	s.Equal(testCookieName, c.Name)
	s.Equal(testCookiePath, c.Path)
	s.True(c.HttpOnly, "cookie must be HttpOnly")
	s.True(c.Secure, "cookie must be Secure")
	s.Equal(http.SameSiteLaxMode, c.SameSite)
	s.Equal(int(testSessionTTL.Seconds()), c.MaxAge)
	s.Equal(s.signedCookie(testSessionSID), c.Value)
}

func (s *SessionSuite) TestIssueSurfacesSIDGeneratorError() {
	boom := errors.New("entropy source exhausted")
	mgr := oidc.NewSessionManager(s.store, s.key,
		oidc.WithSessionClock(func() time.Time { return testSessionNow }),
		oidc.WithSessionSIDGenerator(func() (string, error) { return "", boom }),
	)
	rec := httptest.NewRecorder()

	_, err := mgr.Issue(s.ctx, rec, testSessionEmail)
	s.Require().Error(err)
	s.Truef(errors.Is(err, boom), "expected sid-generator error to wrap %v, got %v", boom, err)
	s.Zero(s.store.saveCalls)
	s.Empty(rec.Result().Cookies())
}

func (s *SessionSuite) TestIssueSurfacesStoreError() {
	boom := errors.New("disk is on fire")
	s.store.saveErr = boom
	rec := httptest.NewRecorder()

	_, err := s.manager.Issue(s.ctx, rec, testSessionEmail)
	s.Require().Error(err)
	s.Truef(errors.Is(err, boom), "expected store save error to wrap %v, got %v", boom, err)
	// No cookie should be set if persistence failed — otherwise the browser
	// would carry an opaque sid that never resolves on lookup.
	s.Empty(rec.Result().Cookies())
}

func (s *SessionSuite) TestGetRoundTrip() {
	rec := httptest.NewRecorder()
	_, err := s.manager.Issue(s.ctx, rec, testSessionEmail)
	s.Require().NoError(err)

	req := httptest.NewRequest(http.MethodGet, "https://tempogate.example.com"+testCookiePath, http.NoBody)
	for _, c := range rec.Result().Cookies() {
		req.AddCookie(c)
	}

	got, err := s.manager.Get(s.ctx, req)
	s.Require().NoError(err)
	s.Equal(testSessionSID, got.SID)
	s.Equal(testSessionEmail, got.Email)
}

func (s *SessionSuite) TestGetRejectsBadInputs() {
	// Seed a valid row so only the cookie variations are responsible for
	// each failure mode the test asserts.
	rec := httptest.NewRecorder()
	_, err := s.manager.Issue(s.ctx, rec, testSessionEmail)
	s.Require().NoError(err)
	validValue := rec.Result().Cookies()[0].Value

	mangledMAC := func() string {
		parts := strings.SplitN(validValue, ".", 2)
		raw, decErr := base64.RawURLEncoding.DecodeString(parts[1])
		s.Require().NoError(decErr)
		raw[0] ^= 0x01
		return parts[0] + "." + base64.RawURLEncoding.EncodeToString(raw)
	}()

	cases := []struct {
		name   string
		cookie *http.Cookie
	}{
		{"missing cookie", nil},
		{"no separator", &http.Cookie{Name: testCookieName, Value: "no-dot-here"}},
		{"empty sid part", &http.Cookie{Name: testCookieName, Value: "." + strings.SplitN(validValue, ".", 2)[1]}},
		{"empty mac part", &http.Cookie{Name: testCookieName, Value: strings.SplitN(validValue, ".", 2)[0] + "."}},
		{"sid not base64", &http.Cookie{Name: testCookieName, Value: "not-base64!!!" + "." + strings.SplitN(validValue, ".", 2)[1]}},
		{"mac not base64", &http.Cookie{Name: testCookieName, Value: strings.SplitN(validValue, ".", 2)[0] + ".not-base64!!!"}},
		{"bit-flipped mac fails constant-time compare", &http.Cookie{Name: testCookieName, Value: mangledMAC}},
	}

	for _, tc := range cases {
		s.Run(tc.name, func() {
			req := httptest.NewRequest(http.MethodGet, "https://tempogate.example.com"+testCookiePath, http.NoBody)
			if tc.cookie != nil {
				req.AddCookie(tc.cookie)
			}

			_, err := s.manager.Get(s.ctx, req)
			s.Require().Error(err)
			s.Truef(errors.Is(err, oidc.ErrNoSession),
				"expected ErrNoSession, got %v", err)
		})
	}
}

func (s *SessionSuite) TestGetRejectsDeletedRow() {
	rec := httptest.NewRecorder()
	_, err := s.manager.Issue(s.ctx, rec, testSessionEmail)
	s.Require().NoError(err)

	s.Require().NoError(s.store.DeleteBrowserSession(s.ctx, testSessionSID))

	req := httptest.NewRequest(http.MethodGet, "https://tempogate.example.com"+testCookiePath, http.NoBody)
	for _, c := range rec.Result().Cookies() {
		req.AddCookie(c)
	}

	_, err = s.manager.Get(s.ctx, req)
	s.Require().Error(err)
	s.Truef(errors.Is(err, oidc.ErrNoSession), "expected ErrNoSession, got %v", err)
}

func (s *SessionSuite) TestGetRejectsExpiredRow() {
	rec := httptest.NewRecorder()
	_, err := s.manager.Issue(s.ctx, rec, testSessionEmail)
	s.Require().NoError(err)

	// Build a manager that sees a clock past the row's ExpiresAt so the TTL
	// check fails without touching the persisted row.
	expired := oidc.NewSessionManager(s.store, s.key,
		oidc.WithSessionClock(func() time.Time { return testSessionNow.Add(testSessionTTL + time.Second) }),
		oidc.WithSessionTTL(testSessionTTL),
		oidc.WithSessionSIDGenerator(func() (string, error) { return testSessionSID, nil }),
	)

	req := httptest.NewRequest(http.MethodGet, "https://tempogate.example.com"+testCookiePath, http.NoBody)
	for _, c := range rec.Result().Cookies() {
		req.AddCookie(c)
	}

	_, err = expired.Get(s.ctx, req)
	s.Require().Error(err)
	s.Truef(errors.Is(err, oidc.ErrNoSession), "expected ErrNoSession, got %v", err)
}

func (s *SessionSuite) TestGetSurfacesUnexpectedLookupError() {
	boom := errors.New("database is sleeping")
	s.store.lookupErr = boom

	rec := httptest.NewRecorder()
	// Forge a syntactically-valid cookie so Get reaches the store.
	cookie := &http.Cookie{Name: testCookieName, Value: s.signedCookie(testSessionSID), Path: testCookiePath}
	req := httptest.NewRequest(http.MethodGet, "https://tempogate.example.com"+testCookiePath, http.NoBody)
	req.AddCookie(cookie)
	_ = rec

	_, err := s.manager.Get(s.ctx, req)
	s.Require().Error(err)
	s.Truef(errors.Is(err, boom), "expected lookup error to wrap %v, got %v", boom, err)
	s.Falsef(errors.Is(err, oidc.ErrNoSession),
		"unexpected store errors must not be swallowed into ErrNoSession")
}

func (s *SessionSuite) TestClearRemovesRowAndExpiresCookie() {
	rec := httptest.NewRecorder()
	_, err := s.manager.Issue(s.ctx, rec, testSessionEmail)
	s.Require().NoError(err)
	s.Require().Equal(1, s.store.count())

	req := httptest.NewRequest(http.MethodGet, "https://tempogate.example.com"+testCookiePath, http.NoBody)
	for _, c := range rec.Result().Cookies() {
		req.AddCookie(c)
	}

	w := httptest.NewRecorder()
	s.Require().NoError(s.manager.Clear(s.ctx, w, req))

	s.Zero(s.store.count())
	s.Equal(1, s.store.deleteCalls)

	cookies := w.Result().Cookies()
	s.Require().Len(cookies, 1)
	c := cookies[0]
	s.Equal(testCookieName, c.Name)
	s.Equal(testCookiePath, c.Path)
	s.Equal(-1, c.MaxAge, "expired cookie must use MaxAge=-1 so the browser drops it immediately")
}

func (s *SessionSuite) TestClearWithoutCookieIsNoOp() {
	req := httptest.NewRequest(http.MethodGet, "https://tempogate.example.com"+testCookiePath, http.NoBody)
	w := httptest.NewRecorder()

	s.Require().NoError(s.manager.Clear(s.ctx, w, req))
	// No row to delete, but a Max-Age=-1 cookie still goes out so a stale
	// cookie carried by a misbehaving client gets cleared on next response.
	s.Zero(s.store.deleteCalls)
	cookies := w.Result().Cookies()
	s.Require().Len(cookies, 1)
	s.Equal(-1, cookies[0].MaxAge)
}

func (s *SessionSuite) TestClearMangledCookieDoesNotHitStore() {
	req := httptest.NewRequest(http.MethodGet, "https://tempogate.example.com"+testCookiePath, http.NoBody)
	req.AddCookie(&http.Cookie{Name: testCookieName, Value: "garbage-without-dot"})
	w := httptest.NewRecorder()

	s.Require().NoError(s.manager.Clear(s.ctx, w, req))
	// Mangled cookies have no recoverable sid, so Clear cannot target a row
	// but must still emit the eviction cookie so the browser drops the value.
	s.Zero(s.store.deleteCalls)
	cookies := w.Result().Cookies()
	s.Require().Len(cookies, 1)
	s.Equal(-1, cookies[0].MaxAge)
}

// TestCookieAttributesAreFixed pins the security-critical attributes of the
// issued cookie. Secure / HttpOnly / SameSite=Lax are not operator-tunable
// — every code path must emit a cookie the browser refuses to send over
// plain http, hides from javascript, and withholds on cross-site POSTs.
// Path and Name are configurable; the rest is not.
func (s *SessionSuite) TestCookieAttributesAreFixed() {
	mgr := oidc.NewSessionManager(s.store, s.key,
		oidc.WithSessionClock(func() time.Time { return testSessionNow }),
		oidc.WithSessionSIDGenerator(func() (string, error) { return testSessionSID, nil }),
	)
	rec := httptest.NewRecorder()
	_, err := mgr.Issue(s.ctx, rec, testSessionEmail)
	s.Require().NoError(err)

	cookies := rec.Result().Cookies()
	s.Require().Len(cookies, 1)
	c := cookies[0]
	s.True(c.Secure, "Secure must be set")
	s.True(c.HttpOnly, "HttpOnly must be set")
	s.Equal(http.SameSiteLaxMode, c.SameSite, "SameSite must be Lax")
	s.Equal(testCookieName, c.Name)
	s.Equal(testCookiePath, c.Path)
}

func (s *SessionSuite) TestCookieNameAndPathOverride() {
	mgr := oidc.NewSessionManager(s.store, s.key,
		oidc.WithSessionClock(func() time.Time { return testSessionNow }),
		oidc.WithSessionSIDGenerator(func() (string, error) { return testSessionSID, nil }),
		oidc.WithCookieName("custom_name"),
		oidc.WithCookiePath("/some/path"),
	)
	rec := httptest.NewRecorder()
	_, err := mgr.Issue(s.ctx, rec, testSessionEmail)
	s.Require().NoError(err)

	c := rec.Result().Cookies()[0]
	s.Equal("custom_name", c.Name)
	s.Equal("/some/path", c.Path)
	// Security attributes stay locked even when Name/Path are overridden.
	s.True(c.Secure)
	s.True(c.HttpOnly)
	s.Equal(http.SameSiteLaxMode, c.SameSite)
}

func (s *SessionSuite) TestDefaultTTLIsFiveMinutes() {
	mgr := oidc.NewSessionManager(s.store, s.key,
		oidc.WithSessionClock(func() time.Time { return testSessionNow }),
		oidc.WithSessionSIDGenerator(func() (string, error) { return testSessionSID, nil }),
		// No WithSessionTTL → must default to 5m per the architecture decision.
	)
	rec := httptest.NewRecorder()
	_, err := mgr.Issue(s.ctx, rec, testSessionEmail)
	s.Require().NoError(err)

	saved := s.store.only()
	s.True(saved.ExpiresAt.Equal(testSessionNow.Add(5*time.Minute)),
		"default TTL must be 5 minutes; got %v", saved.ExpiresAt.Sub(saved.CreatedAt))
}
