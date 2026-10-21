package oidc_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"

	"github.com/onhotpath/tempogate/oidc"
	"github.com/onhotpath/tempogate/ratelimit"
)

// device_hardening_test.go pins the RFC 8628 §5.1 user_code guessing
// defences and the same-origin / MAC hygiene of the verification UI: one
// uniform message for every unusable code, per-IP and per-session attempt
// limits, a parsed Referer comparison, and domain-separated HMACs.

// rateLimitedMarker is the substring every throttled verification page
// carries. Shared so the tests do not each restate the copy.
const rateLimitedMarker = "Too many attempts"

// assertUnusableCodesShareOnePage: unknown, expired, approved and denied
// codes must render byte-identical pages on every surface that looks a code
// up, so a guesser cannot tell "no such code" from "a real code in a state I
// cannot use". Four attempts per test stay inside the per-session budget.
func (s *DeviceUISuite) assertUnusableCodesShareOnePage(build func(code, cookie string) *http.Request) {
	cookieValue := s.seedSession()
	for _, dc := range []oidc.DeviceCode{
		{
			Code: "expired-dc", UserCode: "CCCCCCCC", ClientID: "tempogate-device",
			CreatedAt: deviceUINow.Add(-time.Hour), ExpiresAt: deviceUINow.Add(-time.Minute),
		},
		{
			Code: "approved-dc", UserCode: "DDDDDDDD", ClientID: "tempogate-device",
			CreatedAt: deviceUINow, ExpiresAt: deviceUINow.Add(15 * time.Minute), ApprovedAt: ptr(deviceUINow),
		},
		{
			Code: "denied-dc", UserCode: "FFFFFFFF", ClientID: "tempogate-device",
			CreatedAt: deviceUINow, ExpiresAt: deviceUINow.Add(15 * time.Minute), DeniedAt: ptr(deviceUINow),
		},
	} {
		s.store.put(dc)
	}
	var first string
	for _, code := range []string{"ZZZZ-ZZZZ", "CCCC-CCCC", "DDDD-DDDD", "FFFF-FFFF"} {
		resp, err := s.client.Do(build(code, cookieValue))
		s.Require().NoError(err)
		body := readBody(s.T(), resp)
		resp.Body.Close()
		s.Equal(http.StatusOK, resp.StatusCode, code)
		if first == "" {
			first = body
			continue
		}
		s.Equalf(first, body, "%s must render the same page as an unknown code", code)
	}
	s.Zero(s.store.countApproved())
	s.Zero(s.store.countDenied())
}

func (s *DeviceUISuite) TestUnusableCodesShareOnePageOnEnter() {
	s.assertUnusableCodesShareOnePage(func(code, cookie string) *http.Request {
		r := s.post("/device", url.Values{"user_code": {code}})
		r.Header.Set("Cookie", cookie)
		return r
	})
}

func (s *DeviceUISuite) TestUnusableCodesShareOnePageOnConfirm() {
	s.assertUnusableCodesShareOnePage(func(code, cookie string) *http.Request {
		r := s.req(http.MethodGet, "/device/confirm?user_code="+code)
		r.Header.Set("Cookie", cookie)
		return r
	})
}

func (s *DeviceUISuite) TestUnusableCodesShareOnePageOnApprove() {
	s.assertUnusableCodesShareOnePage(func(code, cookie string) *http.Request {
		r := s.post("/device/approve", url.Values{"csrf_token": {deviceUITestSID}, "user_code": {code}})
		r.Header.Set("Cookie", cookie)
		return r
	})
}

func (s *DeviceUISuite) TestUnusableCodesShareOnePageOnDeny() {
	s.assertUnusableCodesShareOnePage(func(code, cookie string) *http.Request {
		r := s.post("/device/deny", url.Values{"csrf_token": {deviceUITestSID}, "user_code": {code}})
		r.Header.Set("Cookie", cookie)
		return r
	})
}

// TestUserCodeEntryIsRateLimitedPerIP: an unauthenticated client guessing
// codes on POST /device is throttled after the per-IP budget, and once
// throttled even a valid code gets the same 429 page (no oracle).
func (s *DeviceUISuite) TestUserCodeEntryIsRateLimitedPerIP() {
	limited := -1
	for i := range 40 {
		resp, err := s.client.Do(s.post("/device", url.Values{"user_code": {"ZZZZ-ZZZZ"}}))
		s.Require().NoError(err)
		body := readBody(s.T(), resp)
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			s.Contains(body, rateLimitedMarker)
			limited = i
			break
		}
		s.Equal(http.StatusOK, resp.StatusCode)
	}
	s.Require().Equal(20, limited, "the 21st failed guess from one IP must be throttled")

	resp, err := s.client.Do(s.post("/device", url.Values{"user_code": {deviceUITestUserDisplay}}))
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusTooManyRequests, resp.StatusCode, "a valid code must not bypass the throttle")
	s.Contains(readBody(s.T(), resp), rateLimitedMarker)
}

// TestUserCodeAttemptsAreRateLimitedPerSession: a signed-in user guessing
// someone else's code on the approve endpoint is throttled by the tighter
// per-session budget, well before the per-IP one.
func (s *DeviceUISuite) TestUserCodeAttemptsAreRateLimitedPerSession() {
	cookieValue := s.seedSession()
	limited := -1
	for i := range 20 {
		r := s.post("/device/approve", url.Values{"csrf_token": {deviceUITestSID}, "user_code": {"ZZZZ-ZZZZ"}})
		r.Header.Set("Cookie", cookieValue)
		resp, err := s.client.Do(r)
		s.Require().NoError(err)
		body := readBody(s.T(), resp)
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			s.Contains(body, rateLimitedMarker)
			limited = i
			break
		}
	}
	s.Require().Equal(5, limited, "the 6th failed guess from one session must be throttled")
	s.Zero(s.store.countApproved())
}

// TestValidUserCodeAttemptsDoNotSpendTheBudget: a legitimate user (or an
// office behind one NAT) who completes several flows in a minute must not
// trip the limiter; only failed lookups count.
func (s *DeviceUISuite) TestValidUserCodeAttemptsDoNotSpendTheBudget() {
	cookieValue := s.seedSession()
	for range 30 {
		r := s.post("/device", url.Values{"user_code": {deviceUITestUserDisplay}})
		r.Header.Set("Cookie", cookieValue)
		resp, err := s.client.Do(r)
		s.Require().NoError(err)
		resp.Body.Close()
		s.Require().Equal(http.StatusSeeOther, resp.StatusCode)
	}
}

// TestDecisionRejectsLookalikeReferer: with Origin absent, the Referer must
// be same-origin with the issuer after parsing. A raw prefix match would let
// https://tempogate.example.com.evil.com through.
func (s *DeviceUISuite) TestDecisionRejectsLookalikeReferer() {
	cookieValue := s.seedSession()
	for _, referer := range []string{
		testIssuer + ".evil.com/device/confirm",
		testIssuer + "@evil.com/device/confirm",
		testIssuer + ":8443/device/confirm",
		"http://tempogate.example.com/device/confirm",
		"not a url at all",
	} {
		s.Run(referer, func() {
			r := s.post("/device/approve", url.Values{"csrf_token": {deviceUITestSID}, "user_code": {deviceUITestUserDisplay}})
			r.Header.Set("Cookie", cookieValue)
			r.Header.Del("Origin")
			r.Header.Set("Referer", referer)
			resp, err := s.client.Do(r)
			s.Require().NoError(err)
			defer resp.Body.Close()
			s.Contains(readBody(s.T(), resp), "did not come from the expected page")
			s.Zero(s.store.countApproved())
		})
	}
}

// TestDecisionRefererHonoursIssuerPathBoundary: under a sub-path issuer the
// Referer path must sit under the issuer path on a "/" boundary; a sibling
// path that merely shares the prefix ("/idpevil") is another app.
func TestDecisionRefererHonoursIssuerPathBoundary(t *testing.T) {
	const issuer = testIssuer + "/idp"
	h := newDeviceUIHarness(t, issuer)
	cases := []struct {
		referer string
		ok      bool
	}{
		{issuer + "/device/confirm?user_code=" + deviceUITestUserDisplay, true},
		{issuer, true},
		{testIssuer + "/idpevil/device/confirm", false},
		{testIssuer + "/device/confirm", false},
	}
	for _, tc := range cases {
		t.Run(tc.referer, func(t *testing.T) {
			h.store.put(oidc.DeviceCode{
				Code: "fixed-device-code", UserCode: deviceUITestUserCanonical, ClientID: "tempogate-device",
				CreatedAt: deviceUINow, ExpiresAt: deviceUINow.Add(15 * time.Minute),
			})
			r := h.post(t, "/device/approve", url.Values{"csrf_token": {deviceUITestSID}, "user_code": {deviceUITestUserDisplay}})
			r.Header.Del("Origin")
			r.Header.Set("Referer", tc.referer)
			resp, err := h.client.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body := readBody(t, resp)
			if got := strings.Contains(body, "Device approved"); got != tc.ok {
				t.Fatalf("referer %q: approved=%v, want %v\n%s", tc.referer, got, tc.ok, body)
			}
		})
	}
}

// TestBounceStateRejectsSessionCookieMAC: the session cookie and the bounce
// state share OIDC_SESSION_SIGNING_KEY and the same "payload.mac" shape, so
// without domain separation a value minted by one verifies as the other.
// Mint a cookie whose sid is a well-formed bounce-state payload and present
// it as the state: it must be refused.
func (s *DeviceUISuite) TestBounceStateRejectsSessionCookieMAC() {
	payload, err := json.Marshal(map[string]any{
		"user_code": deviceUITestUserCanonical,
		"nonce":     "cross-protocol",
		"exp":       deviceUINow.Add(time.Minute).Unix(),
	})
	s.Require().NoError(err)
	minting := oidc.NewSessionManager(newMemBrowserSessionStore(), s.key,
		oidc.WithSessionClock(func() time.Time { return deviceUINow }),
		oidc.WithSessionSIDGenerator(func() (string, error) { return string(payload), nil }),
	)
	_, cookie, err := minting.IssueCookie(s.T().Context(), deviceUITestEmail)
	s.Require().NoError(err)

	resp, err := s.client.Do(s.req(http.MethodGet, "/device/sso-callback?code=auth-code&state="+url.QueryEscape(cookie.Value)))
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode, "a session-cookie MAC must not verify as a bounce state")
	s.Contains(readBody(s.T(), resp), "could not be completed")
	s.Zero(s.redeemer.callCount())
}

// TestBounceStateRejectsUnlabelledMAC: a state signed the pre-separation way
// (bare HMAC over the payload) no longer verifies. In-flight bounces minted
// before an upgrade fail once and the user restarts the sign-in.
func (s *DeviceUISuite) TestBounceStateRejectsUnlabelledMAC() {
	payload, err := json.Marshal(map[string]any{
		"user_code": deviceUITestUserCanonical,
		"nonce":     deviceUITestStateNonce,
		"exp":       deviceUINow.Add(time.Minute).Unix(),
	})
	s.Require().NoError(err)
	state := encodeSigned(payload, hmacOf(s.key, payload))

	resp, err := s.client.Do(s.req(http.MethodGet, "/device/sso-callback?code=auth-code&state="+url.QueryEscape(state)))
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Contains(readBody(s.T(), resp), "could not be completed")
	s.Zero(s.redeemer.callCount())
}

// TestNewDeviceUIRejectsCallbackNotRegisteredForIssuer: the internal client
// must be registered for exactly <issuer>/device/sso-callback, otherwise
// /authorize rejects every bounce at runtime. Fail at construction instead.
func TestNewDeviceUIRejectsCallbackNotRegisteredForIssuer(t *testing.T) {
	cases := []struct {
		name, issuer, registered string
		ok                       bool
	}{
		{"exact", testIssuer, testIssuer + "/device/sso-callback", true},
		{"sub-path issuer", testIssuer + "/idp", testIssuer + "/idp/device/sso-callback", true},
		{"loopback port is free", "http://127.0.0.1:8000", "http://127.0.0.1/device/sso-callback", true},
		{"other host", testIssuer, "https://other.example.com/device/sso-callback", false},
		{"missing base path", testIssuer + "/idp", testIssuer + "/device/sso-callback", false},
		{"unparseable issuer", ":::not-a-url", testIssuer + "/device/sso-callback", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reg, err := oidc.ParseClientRegistry("tempogate-device-ui:" + tc.registered)
			if err != nil {
				t.Fatal(err)
			}
			if err := reg.WithSecrets("tempogate-device-ui:" + deviceUIInternalSecret); err != nil {
				t.Fatal(err)
			}
			sessions := oidc.NewSessionManager(newMemBrowserSessionStore(), []byte("0123456789abcdef0123456789abcdef"))
			_, err = oidc.NewDeviceUI(newStatefulDeviceCodeStore(), sessions, reg, newFakeAuthCodeRedeemer(deviceUITestEmail),
				[]byte("0123456789abcdef0123456789abcdef"), tc.issuer)
			if tc.ok && err != nil {
				t.Fatalf("want success, got %v", err)
			}
			if !tc.ok && !errors.Is(err, oidc.ErrInternalDeviceUIClientRedirectMismatch) {
				t.Fatalf("want ErrInternalDeviceUIClientRedirectMismatch, got %v", err)
			}
		})
	}
}

// deviceUIHarness is a minimal DeviceUI over an arbitrary issuer, for tests
// that need something other than the suite's root issuer.
type deviceUIHarness struct {
	store  *statefulDeviceCodeStore
	srv    *httptest.Server
	client *http.Client
	cookie string
	issuer string
}

func newDeviceUIHarness(t *testing.T, issuer string) *deviceUIHarness {
	t.Helper()
	key := []byte("0123456789abcdef0123456789abcdef")
	reg, err := oidc.ParseClientRegistry("tempogate-device:,tempogate-device-ui:" + issuer + "/device/sso-callback")
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.WithSecrets("tempogate-device-ui:" + deviceUIInternalSecret); err != nil {
		t.Fatal(err)
	}
	bs := newMemBrowserSessionStore()
	sessions := oidc.NewSessionManager(bs, key,
		oidc.WithSessionClock(func() time.Time { return deviceUINow }),
		oidc.WithSessionSIDGenerator(func() (string, error) { return deviceUITestSID, nil }),
	)
	_, cookie, err := sessions.IssueCookie(t.Context(), deviceUITestEmail)
	if err != nil {
		t.Fatal(err)
	}
	store := newStatefulDeviceCodeStore()
	ui, err := oidc.NewDeviceUI(store, sessions, reg, newFakeAuthCodeRedeemer(deviceUITestEmail), key, issuer,
		oidc.WithDeviceUIClock(func() time.Time { return deviceUINow }),
	)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	ui.Register(humago.New(mux, huma.DefaultConfig("device-ui-harness", "0.0.0")))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &deviceUIHarness{
		store:  store,
		srv:    srv,
		client: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		cookie: cookie.String(),
		issuer: issuer,
	}
}

func (h *deviceUIHarness) post(t *testing.T, path string, form url.Values) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodPost, h.srv.URL+path, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", testIssuer)
	r.Header.Set("Cookie", h.cookie)
	return r
}

func encodeSigned(payload, mac []byte) string {
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(mac)
}

// TestConfirmIsRateLimitedWithInjectedLimiters: the confirm page spends the
// same budget as the other lookup surfaces, and WithUserCodeRateLimiters
// swaps the limiters, here to a one-failure session budget.
func (s *DeviceUISuite) TestConfirmIsRateLimitedWithInjectedLimiters() {
	ui, err := oidc.NewDeviceUI(s.store, s.sessions, s.clients, s.redeemer, s.key, testIssuer,
		oidc.WithDeviceUIClock(func() time.Time { return deviceUINow }),
		oidc.WithUserCodeRateLimiters(
			ratelimit.New(ratelimit.WithLimit(100, time.Minute)),
			ratelimit.New(ratelimit.WithLimit(1, time.Hour)),
		),
	)
	s.Require().NoError(err)
	mux := http.NewServeMux()
	ui.Register(humago.New(mux, huma.DefaultConfig("device-ui-limited", "0.0.0")))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	cookieValue := s.seedSession()

	confirm := func(code string) (int, string) {
		r, err := http.NewRequest(http.MethodGet, srv.URL+"/device/confirm?user_code="+code, http.NoBody)
		s.Require().NoError(err)
		r.Header.Set("Cookie", cookieValue)
		resp, err := s.client.Do(r)
		s.Require().NoError(err)
		defer resp.Body.Close()
		return resp.StatusCode, readBody(s.T(), resp)
	}

	status, body := confirm(deviceUITestUserDisplay)
	s.Equal(http.StatusOK, status)
	s.Contains(body, "csrf_token", "a live code costs nothing")

	status, body = confirm("ZZZZ-ZZZZ")
	s.Equal(http.StatusOK, status)
	s.Contains(body, "That code is not valid")

	status, body = confirm(deviceUITestUserDisplay)
	s.Equal(http.StatusTooManyRequests, status, "the session budget is spent, even a live code is refused")
	s.Contains(body, rateLimitedMarker)
}
