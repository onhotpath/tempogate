package oidc_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/stretchr/testify/suite"

	"github.com/onhotpath/tempogate/oidc"
)

func stdHMACSHA256(key []byte) hash.Hash { return hmac.New(sha256.New, key) }

const (
	deviceUITestUserCanonical = "BCDFGHJK"
	deviceUITestUserDisplay   = "BCDF-GHJK"
	deviceUITestSID           = "fixed-device-ui-sid"
	deviceUITestEmail         = "alice@example.com"
	deviceUITestStateNonce    = "fixed-state-nonce"
	deviceUIInternalSecret    = "device-ui-secret"
	deviceUIClientsRaw        = "tempogate-device:cli,tempogate-device-ui:https://tempogate.example.com/device/sso-callback"
)

var deviceUINow = time.Unix(1700000000, 0).UTC()

// statefulDeviceCodeStore is a richer in-memory store than memDeviceCodeStore:
// the device-ui tests need a live LookupDeviceCodeByUserCode and a flipping
// Approve/Deny because both sit on the happy path. Other methods are stubs
// since the verification UI does not exercise them.
type statefulDeviceCodeStore struct {
	mu         sync.Mutex
	byUser     map[string]oidc.DeviceCode
	approved   []deviceDecision
	denied     []deviceDecision
	lookupErr  error
	approveErr error
	denyErr    error
}

type deviceDecision struct {
	UserCode string
	Email    string
	At       time.Time
}

func newStatefulDeviceCodeStore() *statefulDeviceCodeStore {
	return &statefulDeviceCodeStore{byUser: map[string]oidc.DeviceCode{}}
}

func (s *statefulDeviceCodeStore) put(dc oidc.DeviceCode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byUser[dc.UserCode] = dc
}

func (s *statefulDeviceCodeStore) SaveDeviceCode(_ context.Context, dc oidc.DeviceCode) error {
	s.put(dc)
	return nil
}

func (s *statefulDeviceCodeStore) LookupDeviceCodeByDeviceCode(_ context.Context, _ string) (oidc.DeviceCode, error) {
	return oidc.DeviceCode{}, oidc.ErrDeviceCodeNotFound
}

func (s *statefulDeviceCodeStore) LookupDeviceCodeByUserCode(_ context.Context, userCode string) (oidc.DeviceCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lookupErr != nil {
		return oidc.DeviceCode{}, s.lookupErr
	}
	dc, ok := s.byUser[userCode]
	if !ok {
		return oidc.DeviceCode{}, oidc.ErrDeviceCodeNotFound
	}
	return dc, nil
}

func (s *statefulDeviceCodeStore) TouchDeviceCodePoll(_ context.Context, _ string, _ time.Time, _ bool) error {
	return nil
}

func (s *statefulDeviceCodeStore) ApproveDeviceCode(_ context.Context, userCode, email string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.approveErr != nil {
		return s.approveErr
	}
	dc, ok := s.byUser[userCode]
	if !ok {
		return oidc.ErrDeviceCodeNotFound
	}
	if dc.ApprovedAt != nil || dc.DeniedAt != nil {
		return oidc.ErrDeviceCodeNotPending
	}
	dc.ApprovedAt = &now
	dc.Email = email
	s.byUser[userCode] = dc
	s.approved = append(s.approved, deviceDecision{UserCode: userCode, Email: email, At: now})
	return nil
}

func (s *statefulDeviceCodeStore) DenyDeviceCode(_ context.Context, userCode string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.denyErr != nil {
		return s.denyErr
	}
	dc, ok := s.byUser[userCode]
	if !ok {
		return oidc.ErrDeviceCodeNotFound
	}
	if dc.ApprovedAt != nil || dc.DeniedAt != nil {
		return oidc.ErrDeviceCodeNotPending
	}
	dc.DeniedAt = &now
	s.byUser[userCode] = dc
	s.denied = append(s.denied, deviceDecision{UserCode: userCode, At: now})
	return nil
}

func (s *statefulDeviceCodeStore) ConsumeDeviceCode(_ context.Context, _ string) (oidc.DeviceCode, error) {
	return oidc.DeviceCode{}, oidc.ErrDeviceCodeNotFound
}

func (s *statefulDeviceCodeStore) countApproved() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.approved)
}

func (s *statefulDeviceCodeStore) countDenied() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.denied)
}

// fakeAuthCodeRedeemer stands in for the in-process *Token.RedeemAuthorizationCode
// the SSO callback calls. Tests pre-stage the email (happy path) or an error
// (failure path), and inspect lastReq to assert the exact AuthCodeRedemptionRequest
// the device-flow surface built before handing it to the redeemer.
type fakeAuthCodeRedeemer struct {
	mu      sync.Mutex
	email   string
	err     error
	calls   int
	lastReq oidc.AuthCodeRedemptionRequest
}

func newFakeAuthCodeRedeemer(email string) *fakeAuthCodeRedeemer {
	return &fakeAuthCodeRedeemer{email: email}
}

func (f *fakeAuthCodeRedeemer) RedeemAuthorizationCode(_ context.Context, in oidc.AuthCodeRedemptionRequest) (*oidc.AuthCodeRedemption, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.lastReq = in
	if f.err != nil {
		return nil, f.err
	}
	return &oidc.AuthCodeRedemption{Email: f.email, ClientID: in.ClientID}, nil
}

func (f *fakeAuthCodeRedeemer) setErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

func (f *fakeAuthCodeRedeemer) snapshotLastReq() oidc.AuthCodeRedemptionRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastReq
}

func (f *fakeAuthCodeRedeemer) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

type DeviceUISuite struct {
	suite.Suite

	store    *statefulDeviceCodeStore
	sessions *oidc.SessionManager
	bsStore  *memBrowserSessionStore
	ui       *oidc.DeviceUI
	srv      *httptest.Server
	redeemer *fakeAuthCodeRedeemer
	client   *http.Client
	clients  oidc.ClientRegistry
	key      []byte
}

func TestDeviceUISuite(t *testing.T) {
	suite.Run(t, new(DeviceUISuite))
}

func (s *DeviceUISuite) SetupTest() {
	s.key = []byte("0123456789abcdef0123456789abcdef")

	s.store = newStatefulDeviceCodeStore()
	s.store.put(oidc.DeviceCode{
		Code:            "fixed-device-code",
		UserCode:        deviceUITestUserCanonical,
		ClientID:        "tempogate-device",
		Scope:           "openid email",
		IntervalSeconds: 5,
		CreatedAt:       deviceUINow,
		ExpiresAt:       deviceUINow.Add(15 * time.Minute),
	})

	s.bsStore = newMemBrowserSessionStore()
	s.sessions = oidc.NewSessionManager(s.bsStore, s.key,
		oidc.WithSessionClock(func() time.Time { return deviceUINow }),
		oidc.WithSessionTTL(5*time.Minute),
		oidc.WithSessionSIDGenerator(func() (string, error) { return deviceUITestSID, nil }),
	)

	reg, err := oidc.ParseClientRegistry(deviceUIClientsRaw)
	s.Require().NoError(err)
	s.Require().NoError(reg.WithSecrets("tempogate-device-ui:" + deviceUIInternalSecret))
	s.clients = reg

	s.redeemer = newFakeAuthCodeRedeemer(deviceUITestEmail)

	ui, err := oidc.NewDeviceUI(s.store, s.sessions, s.clients, s.redeemer, s.key, testIssuer,
		oidc.WithDeviceUIClock(func() time.Time { return deviceUINow }),
		oidc.WithDeviceUIStateNonceGenerator(func() (string, error) { return deviceUITestStateNonce, nil }),
	)
	s.Require().NoError(err)
	s.ui = ui

	mux := http.NewServeMux()
	s.ui.Register(humago.New(mux, huma.DefaultConfig("device-ui-test", "0.0.0")))
	s.srv = httptest.NewServer(mux)

	s.client = &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (s *DeviceUISuite) TearDownTest() {
	s.srv.Close()
}

// seedSession injects a valid signed cookie into a request so the handler's
// SessionManager.Get path resolves to a live session without going through
// the SSO bounce. The cookie value mirrors what SessionManager.IssueCookie
// would produce: base64url(sid).base64url(HMAC-SHA256(key, sid)).
func (s *DeviceUISuite) seedSession() string {
	s.Require().NoError(s.bsStore.SaveBrowserSession(context.Background(), oidc.BrowserSession{
		SID:       deviceUITestSID,
		Email:     deviceUITestEmail,
		CreatedAt: deviceUINow,
		ExpiresAt: deviceUINow.Add(5 * time.Minute),
	}))
	rec := httptest.NewRecorder()
	_, cookie, err := s.sessions.IssueCookie(context.Background(), deviceUITestEmail)
	s.Require().NoError(err)
	rec.Header().Set("Set-Cookie", cookie.String())
	return cookie.String()
}

func (s *DeviceUISuite) req(method, path string) *http.Request {
	r, err := http.NewRequest(method, s.srv.URL+path, http.NoBody)
	s.Require().NoError(err)
	return r
}

func (s *DeviceUISuite) post(path string, form url.Values) *http.Request {
	r, err := http.NewRequest(http.MethodPost, s.srv.URL+path, strings.NewReader(form.Encode()))
	s.Require().NoError(err)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Origin defaults to the issuer so the same-origin check passes; tests
	// that exercise the rejection path overwrite it explicitly.
	r.Header.Set("Origin", testIssuer)
	return r
}

// TestEnterGetRendersForm covers the happy path of GET /device with no
// prefill: the form renders as text/html with no-store, contains the input
// element, and does not leak any prefilled value.
func (s *DeviceUISuite) TestEnterGetRendersForm() {
	resp, err := s.client.Do(s.req(http.MethodGet, "/device"))
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode)
	s.Contains(resp.Header.Get("Content-Type"), "text/html")
	s.Equal("no-store", resp.Header.Get("Cache-Control"))

	body := readBody(s.T(), resp)
	s.Contains(body, `name="user_code"`)
	s.NotContains(body, `value="BCDF-GHJK"`)
}

// TestEnterGetPrefillsFromQueryString covers the verification_uri_complete
// hop: ?user_code=BCDF-GHJK seeds the form's input value with the dashed
// display form, even though the canonical form is what gets persisted.
func (s *DeviceUISuite) TestEnterGetPrefillsFromQueryString() {
	resp, err := s.client.Do(s.req(http.MethodGet, "/device?user_code=BCDF-GHJK"))
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode)

	body := readBody(s.T(), resp)
	s.Contains(body, `value="BCDF-GHJK"`)
}

// TestEnterPostWithSessionGoesStraightToConfirm: when the browser already
// carries a valid session cookie, the POST short-circuits the upstream
// bounce and 303s straight to /device/confirm.
func (s *DeviceUISuite) TestEnterPostWithSessionGoesStraightToConfirm() {
	cookieValue := s.seedSession()

	r := s.post("/device", url.Values{"user_code": {deviceUITestUserDisplay}})
	r.Header.Set("Cookie", cookieValue)
	resp, err := s.client.Do(r)
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Equal(http.StatusSeeOther, resp.StatusCode)
	loc, err := url.Parse(resp.Header.Get("Location"))
	s.Require().NoError(err)
	s.Equal("/device/confirm", loc.Path)
	s.Equal(deviceUITestUserDisplay, loc.Query().Get("user_code"))
}

// TestEnterPostNoSessionBouncesThroughAuthorize: no session cookie ⇒ 303 to
// /authorize?client_id=tempogate-device-ui&...&state=<signed-state>. The
// state is HMAC-signed under the same key the SessionManager uses, so the
// sso-callback can verify it back.
func (s *DeviceUISuite) TestEnterPostNoSessionBouncesThroughAuthorize() {
	r := s.post("/device", url.Values{"user_code": {deviceUITestUserDisplay}})
	resp, err := s.client.Do(r)
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Equal(http.StatusSeeOther, resp.StatusCode)
	loc, err := url.Parse(resp.Header.Get("Location"))
	s.Require().NoError(err)
	s.Equal(testIssuer+"/authorize", loc.Scheme+"://"+loc.Host+loc.Path)
	q := loc.Query()
	s.Equal("tempogate-device-ui", q.Get("client_id"))
	s.Equal(testIssuer+"/device/sso-callback", q.Get("redirect_uri"))
	s.Equal("code", q.Get("response_type"))
	s.NotEmpty(q.Get("state"), "bounce state must be present")
}

func (s *DeviceUISuite) TestEnterPostErrorPaths() {
	cases := []struct {
		name      string
		body      url.Values
		setup     func()
		wantMatch string
	}{
		{
			name:      "missing user_code",
			body:      url.Values{"filler": {"x"}},
			wantMatch: "Enter the code",
		},
		{
			name:      "unknown user_code",
			body:      url.Values{"user_code": {"ZZZZ-ZZZZ"}},
			wantMatch: "not active",
		},
		{
			name: "expired user_code",
			body: url.Values{"user_code": {deviceUITestUserDisplay}},
			setup: func() {
				s.store.put(oidc.DeviceCode{
					Code:      "fixed-device-code",
					UserCode:  deviceUITestUserCanonical,
					ClientID:  "tempogate-device",
					CreatedAt: deviceUINow.Add(-time.Hour),
					ExpiresAt: deviceUINow.Add(-time.Minute),
				})
			},
			wantMatch: "expired",
		},
		{
			name: "already approved",
			body: url.Values{"user_code": {deviceUITestUserDisplay}},
			setup: func() {
				stamp := deviceUINow
				s.store.put(oidc.DeviceCode{
					Code:       "fixed-device-code",
					UserCode:   deviceUITestUserCanonical,
					ClientID:   "tempogate-device",
					CreatedAt:  deviceUINow,
					ExpiresAt:  deviceUINow.Add(15 * time.Minute),
					ApprovedAt: &stamp,
				})
			},
			wantMatch: "already been used",
		},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			if tc.setup != nil {
				tc.setup()
			}
			resp, err := s.client.Do(s.post("/device", tc.body))
			s.Require().NoError(err)
			defer resp.Body.Close()
			s.Equal(http.StatusOK, resp.StatusCode)
			body := readBody(s.T(), resp)
			s.Contains(body, tc.wantMatch)
		})
	}
}

// TestSSOCallbackHappyPath drives the in-process auth-code redemption,
// asserts a session row was minted, and confirms the response carries a
// session cookie + 303 to /device/confirm with the recovered user_code.
// The redeemer's lastReq pins the exact AuthCodeRedemptionRequest the
// callback built — client_id, secret, redirect_uri, code — proving the
// in-process call carries the same parameters the old loopback POST did.
func (s *DeviceUISuite) TestSSOCallbackHappyPath() {
	state := s.signedBounceState(deviceUITestUserCanonical, deviceUITestStateNonce, deviceUINow.Add(time.Minute).Unix())
	resp, err := s.client.Do(s.req(http.MethodGet, "/device/sso-callback?code=auth-code&state="+url.QueryEscape(state)))
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Equal(http.StatusSeeOther, resp.StatusCode)
	loc, err := url.Parse(resp.Header.Get("Location"))
	s.Require().NoError(err)
	s.Equal("/device/confirm", loc.Path)
	s.Equal(deviceUITestUserDisplay, loc.Query().Get("user_code"))

	cookies := resp.Cookies()
	s.Require().Len(cookies, 1, "session cookie must be set on the redirect")
	s.Equal("tempogate_session", cookies[0].Name)
	s.True(cookies[0].HttpOnly)
	s.True(cookies[0].Secure)

	s.Equal(1, s.bsStore.count())
	s.Equal(deviceUITestEmail, s.bsStore.only().Email)
	s.Equal(1, s.redeemer.callCount())
	req := s.redeemer.snapshotLastReq()
	s.Equal("auth-code", req.Code)
	s.Equal("tempogate-device-ui", req.ClientID)
	s.Equal(deviceUIInternalSecret, req.ClientSecret)
	s.Equal(testIssuer+"/device/sso-callback", req.RedirectURI)
	s.Empty(req.CodeVerifier, "the internal device-ui client authenticates by secret, not PKCE")
}

func (s *DeviceUISuite) TestSSOCallbackErrorPaths() {
	cases := []struct {
		name string
		path string
	}{
		{"missing code", "/device/sso-callback?state=anything"},
		{"missing state", "/device/sso-callback?code=auth-code"},
		{"unsigned state", "/device/sso-callback?code=auth-code&state=garbage"},
		{
			"expired state",
			"/device/sso-callback?code=auth-code&state=" +
				url.QueryEscape(signedBounceStateWithKey(deviceUITestUserCanonical, deviceUITestStateNonce, deviceUINow.Add(-time.Hour).Unix(), s.key)),
		},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			resp, err := s.client.Do(s.req(http.MethodGet, tc.path))
			s.Require().NoError(err)
			defer resp.Body.Close()
			s.Equal(http.StatusOK, resp.StatusCode)
			body := readBody(s.T(), resp)
			s.Contains(body, "could not be completed")
		})
	}
}

func (s *DeviceUISuite) TestSSOCallbackTokenFailureRendersError() {
	s.redeemer.setErr(errors.New("simulated redemption failure"))

	state := s.signedBounceState(deviceUITestUserCanonical, deviceUITestStateNonce, deviceUINow.Add(time.Minute).Unix())
	resp, err := s.client.Do(s.req(http.MethodGet, "/device/sso-callback?code=auth-code&state="+url.QueryEscape(state)))
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Equal(http.StatusOK, resp.StatusCode)
	body := readBody(s.T(), resp)
	s.Contains(body, "could not be completed")
	s.Zero(s.bsStore.count(), "no session must be minted when in-process redemption fails")
}

// TestSSOCallbackLogsRedeemAuthCodeFailure pins the operator-visible
// log shape for the SSO callback's most common failure mode: the
// in-process auth-code redemption returning an error (single-use
// already-consumed, expired code, PKCE/secret proof failure, etc.).
// Without a structured log line here the deployment is undiagnosable
// from container stdout.
func (s *DeviceUISuite) TestSSOCallbackLogsRedeemAuthCodeFailure() {
	var buf bytes.Buffer
	ui, srv := s.deviceUIWithLogger(&buf, errors.New("simulated redemption failure"))
	defer srv.Close()
	_ = ui

	state := s.signedBounceState(deviceUITestUserCanonical, deviceUITestStateNonce, deviceUINow.Add(time.Minute).Unix())
	resp, err := s.client.Get(srv.URL + "/device/sso-callback?code=secret-auth-code&state=" + url.QueryEscape(state))
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode)

	line := decodeSingleLogLine(s.T(), buf.Bytes())
	s.Equal("ERROR", line["level"], "in-process redemption failure is an integration error, not a user error")
	s.Equal("device.sso_callback", line["op"])
	s.Equal("redeem_auth_code", line["cause"])
	s.NotEmpty(line["err"], "the underlying error message must reach the operator")
	assertNoSecretLeak(s.T(), buf.Bytes(), []string{"secret-auth-code", deviceUITestStateNonce, deviceUITestSID})
}

// TestSSOCallbackLogsBounceStateVerificationFailure covers the second
// swallowed-error site: a state that decodes but doesn't verify (key
// rotation, expired exp, tampered MAC). Warn-level — recoverable by the
// user re-running the device flow but the rate is operator-relevant.
func (s *DeviceUISuite) TestSSOCallbackLogsBounceStateVerificationFailure() {
	var buf bytes.Buffer
	ui, srv := s.deviceUIWithLogger(&buf, nil)
	defer srv.Close()
	_ = ui

	resp, err := s.client.Get(srv.URL + "/device/sso-callback?code=auth-code&state=garbage-but-non-empty")
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode)

	line := decodeSingleLogLine(s.T(), buf.Bytes())
	s.Equal("WARN", line["level"])
	s.Equal("device.sso_callback", line["op"])
	s.Equal("verify_bounce_state", line["cause"])
	s.NotEmpty(line["err"])
}

// TestSSOCallbackLogsMissingCodeOrState covers the third swallowed-error
// site: a callback hit directly or by a misconfigured upstream client,
// without one of the two required query parameters. Booleans only —
// neither value carries useful content here.
func (s *DeviceUISuite) TestSSOCallbackLogsMissingCodeOrState() {
	var buf bytes.Buffer
	ui, srv := s.deviceUIWithLogger(&buf, nil)
	defer srv.Close()
	_ = ui

	resp, err := s.client.Get(srv.URL + "/device/sso-callback?state=anything")
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode)

	line := decodeSingleLogLine(s.T(), buf.Bytes())
	s.Equal("WARN", line["level"])
	s.Equal("device.sso_callback", line["op"])
	s.Equal("missing_code_or_state", line["cause"])
	s.Equal(false, line["code_present"], "code was absent in the URL")
	s.Equal(true, line["state_present"], "state was present in the URL")
}

// deviceUIWithLogger spins up a fresh DeviceUI + httptest server wired
// with a buffer-backed slog logger so each test owns its log output and
// asserts on it in isolation. redeemerErr controls the in-process
// redemption result — pass nil for tests whose failure is upstream of
// redeemAuthCode, any error to trigger the redeem failure path.
func (s *DeviceUISuite) deviceUIWithLogger(buf *bytes.Buffer, redeemerErr error) (*oidc.DeviceUI, *httptest.Server) {
	redeemer := newFakeAuthCodeRedeemer(deviceUITestEmail)
	if redeemerErr != nil {
		redeemer.setErr(redeemerErr)
	}

	logger := slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ui, err := oidc.NewDeviceUI(s.store, s.sessions, s.clients, redeemer, s.key, testIssuer,
		oidc.WithDeviceUIClock(func() time.Time { return deviceUINow }),
		oidc.WithDeviceUIStateNonceGenerator(func() (string, error) { return deviceUITestStateNonce, nil }),
		oidc.WithDeviceUILogger(logger),
	)
	s.Require().NoError(err)

	mux := http.NewServeMux()
	ui.Register(humago.New(mux, huma.DefaultConfig("device-ui-log-test", "0.0.0")))
	return ui, httptest.NewServer(mux)
}

// decodeSingleLogLine reads exactly one JSON log line from buf and returns
// it as a map. Tests assert one observable line per failure path; multiple
// lines (or none) means the handler emitted the wrong number of records
// and the test should fail loudly rather than silently inspect the first.
func decodeSingleLogLine(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	trimmed := bytes.TrimRight(raw, "\n")
	if len(trimmed) == 0 {
		t.Fatalf("expected one log line, got none")
	}
	if bytes.Contains(trimmed, []byte("\n")) {
		t.Fatalf("expected one log line, got multiple:\n%s", trimmed)
	}
	var m map[string]any
	if err := json.Unmarshal(trimmed, &m); err != nil {
		t.Fatalf("decode log line: %v\n%s", err, trimmed)
	}
	return m
}

// assertNoSecretLeak is a standing guard on the device-ui observability
// surface: no log line may emit secret material. Tests pass in the
// concrete values they injected so a future regression that starts logging
// the auth code, state nonce, or session SID fails loudly here.
func assertNoSecretLeak(t *testing.T, raw []byte, secrets []string) {
	t.Helper()
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("secret %q leaked into log output:\n%s", secret, raw)
		}
	}
}

func (s *DeviceUISuite) TestConfirmNoSessionRedirectsBack() {
	resp, err := s.client.Do(s.req(http.MethodGet, "/device/confirm?user_code="+deviceUITestUserDisplay))
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Equal(http.StatusSeeOther, resp.StatusCode)
	loc, err := url.Parse(resp.Header.Get("Location"))
	s.Require().NoError(err)
	s.Equal("/device", loc.Path)
	s.Equal(deviceUITestUserDisplay, loc.Query().Get("user_code"))
}

func (s *DeviceUISuite) TestConfirmMissingUserCodeIsError() {
	cookieValue := s.seedSession()
	r := s.req(http.MethodGet, "/device/confirm")
	r.Header.Set("Cookie", cookieValue)
	resp, err := s.client.Do(r)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode)
	body := readBody(s.T(), resp)
	s.Contains(body, "could not be completed")
}

func (s *DeviceUISuite) TestConfirmRendersApprovalForm() {
	cookieValue := s.seedSession()
	r := s.req(http.MethodGet, "/device/confirm?user_code="+deviceUITestUserDisplay)
	r.Header.Set("Cookie", cookieValue)
	resp, err := s.client.Do(r)
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Equal(http.StatusOK, resp.StatusCode)
	body := readBody(s.T(), resp)
	s.Contains(body, deviceUITestUserDisplay, "display user_code must be visible to the human verifying it")
	s.Contains(body, deviceUITestEmail)
	s.Contains(body, `action="/device/approve"`)
	s.Contains(body, `action="/device/deny"`)
	s.Contains(body, `name="csrf_token" value="`+deviceUITestSID+`"`)
}

func (s *DeviceUISuite) TestApproveHappyPathFlipsRow() {
	cookieValue := s.seedSession()
	form := url.Values{"csrf_token": {deviceUITestSID}, "user_code": {deviceUITestUserDisplay}}
	r := s.post("/device/approve", form)
	r.Header.Set("Cookie", cookieValue)
	resp, err := s.client.Do(r)
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Equal(http.StatusOK, resp.StatusCode)
	body := readBody(s.T(), resp)
	s.Contains(body, "Device approved")

	s.Equal(1, s.store.countApproved())
	s.Zero(s.store.countDenied())
}

func (s *DeviceUISuite) TestDenyHappyPathFlipsRow() {
	cookieValue := s.seedSession()
	form := url.Values{"csrf_token": {deviceUITestSID}, "user_code": {deviceUITestUserDisplay}}
	r := s.post("/device/deny", form)
	r.Header.Set("Cookie", cookieValue)
	resp, err := s.client.Do(r)
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Equal(http.StatusOK, resp.StatusCode)
	body := readBody(s.T(), resp)
	s.Contains(body, "Device denied")

	s.Zero(s.store.countApproved())
	s.Equal(1, s.store.countDenied())
}

func (s *DeviceUISuite) TestDecisionRejectsBadInputs() {
	cookieValue := s.seedSession()

	cases := []struct {
		name    string
		mutate  func(*http.Request)
		form    url.Values
		wantMsg string
	}{
		{
			name: "no session",
			mutate: func(r *http.Request) {
				r.Header.Del("Cookie")
			},
			form:    url.Values{"csrf_token": {deviceUITestSID}, "user_code": {deviceUITestUserDisplay}},
			wantMsg: "expired",
		},
		{
			name:    "mismatched csrf token",
			form:    url.Values{"csrf_token": {"wrong"}, "user_code": {deviceUITestUserDisplay}},
			wantMsg: "could not be verified",
		},
		{
			name:    "missing csrf token",
			form:    url.Values{"user_code": {deviceUITestUserDisplay}},
			wantMsg: "could not be verified",
		},
		{
			name: "wrong origin",
			mutate: func(r *http.Request) {
				r.Header.Set("Origin", "https://evil.example.com")
			},
			form:    url.Values{"csrf_token": {deviceUITestSID}, "user_code": {deviceUITestUserDisplay}},
			wantMsg: "did not come from the expected page",
		},
		{
			name: "missing origin and referer",
			mutate: func(r *http.Request) {
				r.Header.Del("Origin")
				r.Header.Del("Referer")
			},
			form:    url.Values{"csrf_token": {deviceUITestSID}, "user_code": {deviceUITestUserDisplay}},
			wantMsg: "did not come from the expected page",
		},
		{
			name:    "missing user_code",
			form:    url.Values{"csrf_token": {deviceUITestSID}},
			wantMsg: "missing the device code",
		},
	}

	for _, tc := range cases {
		s.Run(tc.name, func() {
			r := s.post("/device/approve", tc.form)
			r.Header.Set("Cookie", cookieValue)
			if tc.mutate != nil {
				tc.mutate(r)
			}
			resp, err := s.client.Do(r)
			s.Require().NoError(err)
			defer resp.Body.Close()
			s.Equal(http.StatusOK, resp.StatusCode)
			body := readBody(s.T(), resp)
			s.Contains(body, tc.wantMsg)
			s.Zero(s.store.countApproved(), "no row may be flipped on a rejected request")
		})
	}
}

func (s *DeviceUISuite) TestApproveOnAlreadyDecidedRowSurfacesAsError() {
	cookieValue := s.seedSession()
	// Pre-flip the row so Approve sees ErrDeviceCodeNotPending.
	stamp := deviceUINow
	s.store.put(oidc.DeviceCode{
		Code:       "fixed-device-code",
		UserCode:   deviceUITestUserCanonical,
		ClientID:   "tempogate-device",
		CreatedAt:  deviceUINow,
		ExpiresAt:  deviceUINow.Add(15 * time.Minute),
		ApprovedAt: &stamp,
	})

	form := url.Values{"csrf_token": {deviceUITestSID}, "user_code": {deviceUITestUserDisplay}}
	r := s.post("/device/approve", form)
	r.Header.Set("Cookie", cookieValue)
	resp, err := s.client.Do(r)
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Equal(http.StatusOK, resp.StatusCode)
	body := readBody(s.T(), resp)
	s.Contains(body, "already been used")
}

func (s *DeviceUISuite) TestApproveOnUnknownRowSurfacesAsError() {
	cookieValue := s.seedSession()
	s.store.lookupErr = nil
	// Use a user_code that is not in the store.
	form := url.Values{"csrf_token": {deviceUITestSID}, "user_code": {"ZZZZ-ZZZZ"}}
	r := s.post("/device/approve", form)
	r.Header.Set("Cookie", cookieValue)
	resp, err := s.client.Do(r)
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Equal(http.StatusOK, resp.StatusCode)
	body := readBody(s.T(), resp)
	s.Contains(body, "not active")
}

// TestConfirmExpiredOrDecidedRowIsError covers handleConfirm's expired
// and already-used branches — both reachable only after a real session
// has been minted, so the unit-test suite drives them with a seeded
// session + a pre-flipped row.
func (s *DeviceUISuite) TestConfirmExpiredOrDecidedRowIsError() {
	cookieValue := s.seedSession()

	cases := []struct {
		name string
		put  oidc.DeviceCode
		want string
	}{
		{
			name: "expired row",
			put: oidc.DeviceCode{
				Code:      "fixed-device-code",
				UserCode:  deviceUITestUserCanonical,
				ClientID:  "tempogate-device",
				CreatedAt: deviceUINow.Add(-time.Hour),
				ExpiresAt: deviceUINow.Add(-time.Minute),
			},
			want: "expired",
		},
		{
			name: "already approved",
			put: oidc.DeviceCode{
				Code:       "fixed-device-code",
				UserCode:   deviceUITestUserCanonical,
				ClientID:   "tempogate-device",
				CreatedAt:  deviceUINow,
				ExpiresAt:  deviceUINow.Add(15 * time.Minute),
				ApprovedAt: ptr(deviceUINow),
			},
			want: "already been used",
		},
		{
			name: "already denied",
			put: oidc.DeviceCode{
				Code:      "fixed-device-code",
				UserCode:  deviceUITestUserCanonical,
				ClientID:  "tempogate-device",
				CreatedAt: deviceUINow,
				ExpiresAt: deviceUINow.Add(15 * time.Minute),
				DeniedAt:  ptr(deviceUINow),
			},
			want: "already been used",
		},
		{
			name: "unknown row",
			put: oidc.DeviceCode{
				Code:      "fixed-device-code",
				UserCode:  "ZZZZZZZZ", // canonical for the suite is BCDFGHJK, so this row is unreachable by the path
				ClientID:  "tempogate-device",
				CreatedAt: deviceUINow,
				ExpiresAt: deviceUINow.Add(15 * time.Minute),
			},
			want: "not active",
		},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			s.store.byUser = map[string]oidc.DeviceCode{tc.put.UserCode: tc.put}
			r := s.req(http.MethodGet, "/device/confirm?user_code="+deviceUITestUserDisplay)
			r.Header.Set("Cookie", cookieValue)
			resp, err := s.client.Do(r)
			s.Require().NoError(err)
			defer resp.Body.Close()
			s.Equal(http.StatusOK, resp.StatusCode)
			s.Contains(readBody(s.T(), resp), tc.want)
		})
	}
}

// TestEnterPostStateGeneratorErrorIsServerError exercises the bounce-state
// nonce path where the generator returns an error. Such a failure can't
// downgrade into a redirect — it must surface as a server-side 5xx.
func (s *DeviceUISuite) TestEnterPostStateGeneratorErrorIsServerError() {
	failing, err := oidc.NewDeviceUI(s.store, s.sessions, s.clients, s.redeemer, s.key, testIssuer,
		oidc.WithDeviceUIClock(func() time.Time { return deviceUINow }),
		oidc.WithDeviceUIStateNonceGenerator(func() (string, error) { return "", errors.New("entropy exhausted") }),
	)
	s.Require().NoError(err)
	mux := http.NewServeMux()
	failing.Register(humago.New(mux, huma.DefaultConfig("device-ui-failnonce", "0.0.0")))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	r, err := http.NewRequest(http.MethodPost, srv.URL+"/device",
		strings.NewReader(url.Values{"user_code": {deviceUITestUserDisplay}}.Encode()))
	s.Require().NoError(err)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", testIssuer)

	resp, err := s.client.Do(r)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusInternalServerError, resp.StatusCode)
}

// TestOriginAllowedFallsBackToReferer pins the second half of the
// same-origin gate: when Origin is absent but Referer carries the issuer
// prefix, the POST is accepted. The Decision tests already pin the
// rejection paths.
func (s *DeviceUISuite) TestOriginAllowedFallsBackToReferer() {
	cookieValue := s.seedSession()
	form := url.Values{"csrf_token": {deviceUITestSID}, "user_code": {deviceUITestUserDisplay}}
	r := s.post("/device/approve", form)
	r.Header.Set("Cookie", cookieValue)
	r.Header.Del("Origin")
	r.Header.Set("Referer", testIssuer+"/device/confirm?user_code="+deviceUITestUserDisplay)

	resp, err := s.client.Do(r)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode)
	s.Contains(readBody(s.T(), resp), "Device approved")
	s.Equal(1, s.store.countApproved())
}

// TestCanonicalUserCodeStripsAndUppercases pins the lookup normalisation:
// any combination of whitespace, dashes, lowercase, and unrecognised
// punctuation collapses to the upper-case dash-free form the store
// indexes on. Driven through the public POST /device handler because the
// helper is unexported.
func (s *DeviceUISuite) TestCanonicalUserCodeStripsAndUppercases() {
	cases := []string{
		"bcdf-ghjk",       // lowercase + dash
		" BCDF GHJK ",     // spaces
		"BCDF\t-GHJK",     // tab + dash
		"B C D F G H J K", // every-char-spaced
		"BCDF.GHJK!",      // unrecognised punctuation
	}
	cookieValue := s.seedSession()
	for _, raw := range cases {
		s.Run(raw, func() {
			r := s.post("/device", url.Values{"user_code": {raw}})
			r.Header.Set("Cookie", cookieValue)
			resp, err := s.client.Do(r)
			s.Require().NoError(err)
			defer resp.Body.Close()
			// With a valid session the canonical lookup hits the seeded row
			// and 303s to /device/confirm rather than rendering the error
			// page. Any normalisation regression would 404 here.
			s.Equal(http.StatusSeeOther, resp.StatusCode)
			loc, err := url.Parse(resp.Header.Get("Location"))
			s.Require().NoError(err)
			s.Equal("/device/confirm", loc.Path)
		})
	}
}

func ptr[T any](v T) *T { return &v }

// TestMalformedBodyOnPostsIsErrorPage covers handleEnterPost and
// handleDecision's form-parse error branches. Huma already screens an
// empty body with a 400; the path that reaches the parse call is a body
// that decodes but contains invalid percent-encoding.
func (s *DeviceUISuite) TestMalformedBodyOnPostsIsErrorPage() {
	cookieValue := s.seedSession()
	bad := "user_code=%zz%"

	cases := []struct{ name, path string }{
		{"POST /device", "/device"},
		{"POST /device/approve", "/device/approve"},
		{"POST /device/deny", "/device/deny"},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			r, err := http.NewRequest(http.MethodPost, s.srv.URL+tc.path, strings.NewReader(bad))
			s.Require().NoError(err)
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("Origin", testIssuer)
			r.Header.Set("Cookie", cookieValue)
			resp, err := s.client.Do(r)
			s.Require().NoError(err)
			defer resp.Body.Close()
			s.Equal(http.StatusOK, resp.StatusCode)
			s.Contains(readBody(s.T(), resp), "malformed")
		})
	}
}

// TestStoreLookupErrorIs500 covers the not-ErrDeviceCodeNotFound branches
// in handleEnterPost and handleConfirm where the store returns an
// unexpected error. The handler surfaces a 5xx rather than a misleading
// error page so an operator's monitoring sees the underlying issue.
func (s *DeviceUISuite) TestStoreLookupErrorIs500() {
	boom := errors.New("disk fell off")
	s.store.lookupErr = boom

	cases := []struct {
		name   string
		method string
		path   string
		body   string
		cookie bool
	}{
		{"POST /device", http.MethodPost, "/device", "user_code=" + deviceUITestUserDisplay, false},
		{"GET /device/confirm", http.MethodGet, "/device/confirm?user_code=" + deviceUITestUserDisplay, "", true},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			var r *http.Request
			var err error
			if tc.body != "" {
				r, err = http.NewRequest(tc.method, s.srv.URL+tc.path, strings.NewReader(tc.body))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				r.Header.Set("Origin", testIssuer)
			} else {
				r, err = http.NewRequest(tc.method, s.srv.URL+tc.path, http.NoBody)
			}
			s.Require().NoError(err)
			if tc.cookie {
				r.Header.Set("Cookie", s.seedSession())
			}
			resp, err := s.client.Do(r)
			s.Require().NoError(err)
			defer resp.Body.Close()
			s.Equal(http.StatusInternalServerError, resp.StatusCode)
		})
	}
}

// TestSessionUnexpectedLookupErrorIs500 mirrors the device-store sibling
// for the session-store error path: a non-ErrNoSession error must not
// collapse into a redirect or error page.
func (s *DeviceUISuite) TestSessionUnexpectedLookupErrorIs500() {
	s.bsStore.lookupErr = errors.New("session store sick")
	// Build a syntactically-valid cookie so the lookup is actually invoked.
	cookieValue := s.seedSession()
	s.bsStore.lookupErr = errors.New("session store sick")

	cases := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{"POST /device", http.MethodPost, "/device", "user_code=" + deviceUITestUserDisplay},
		{"GET /device/confirm", http.MethodGet, "/device/confirm?user_code=" + deviceUITestUserDisplay, ""},
		{"POST /device/approve", http.MethodPost, "/device/approve", "csrf_token=" + deviceUITestSID + "&user_code=" + deviceUITestUserDisplay},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			var r *http.Request
			var err error
			if tc.body != "" {
				r, err = http.NewRequest(tc.method, s.srv.URL+tc.path, strings.NewReader(tc.body))
				s.Require().NoError(err)
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				r.Header.Set("Origin", testIssuer)
			} else {
				r, err = http.NewRequest(tc.method, s.srv.URL+tc.path, http.NoBody)
				s.Require().NoError(err)
			}
			r.Header.Set("Cookie", cookieValue)

			resp, err := s.client.Do(r)
			s.Require().NoError(err)
			defer resp.Body.Close()
			s.Equal(http.StatusInternalServerError, resp.StatusCode)
		})
	}
}

// TestNewDeviceUITreatsBadIssuerSafely guards originPrefix's "issuer
// does not parse" branch. A device-ui constructed with a non-URL issuer
// still serves the rendered pages, but its Origin gate fails closed so a
// misconfigured server can never accept the Approve form.
func (s *DeviceUISuite) TestNewDeviceUITreatsBadIssuerSafely() {
	ui, err := oidc.NewDeviceUI(s.store, s.sessions, s.clients, s.redeemer, s.key, ":::not-a-url",
		oidc.WithDeviceUIClock(func() time.Time { return deviceUINow }),
		oidc.WithDeviceUIStateNonceGenerator(func() (string, error) { return deviceUITestStateNonce, nil }),
	)
	s.Require().NoError(err, "NewDeviceUI should not fail on a syntactically odd issuer")
	mux := http.NewServeMux()
	ui.Register(humago.New(mux, huma.DefaultConfig("device-ui-badissuer", "0.0.0")))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cookieValue := s.seedSession()
	r, err := http.NewRequest(http.MethodPost, srv.URL+"/device/approve",
		strings.NewReader(url.Values{"csrf_token": {deviceUITestSID}, "user_code": {deviceUITestUserDisplay}}.Encode()))
	s.Require().NoError(err)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Cookie", cookieValue)
	r.Header.Set("Origin", testIssuer)

	resp, err := s.client.Do(r)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode)
	s.Contains(readBody(s.T(), resp), "did not come from the expected page",
		"a parseable Origin against an unparseable issuer must fail closed")
}

// TestSSOCallbackVerifyBounceStateBranches drives the remaining
// verifyBounceState rejection paths — bad MAC, bad payload base64, bad
// MAC base64, JSON that won't decode, and a payload missing the
// user_code. Each must collapse to the same generic error page so a
// probe can't fingerprint which check tripped.
func (s *DeviceUISuite) TestSSOCallbackVerifyBounceStateBranches() {
	validPayload := func(canonical string, exp int64) []byte {
		b, _ := json.Marshal(struct {
			UserCode string `json:"user_code"`
			Nonce    string `json:"nonce"`
			Exp      int64  `json:"exp"`
		}{UserCode: canonical, Nonce: deviceUITestStateNonce, Exp: exp})
		return b
	}

	wrongKey := []byte("ffffffffffffffffffffffffffffffff")

	cases := []struct {
		name  string
		state string
	}{
		{
			"bad MAC",
			signedBounceStateWithKey(deviceUITestUserCanonical, deviceUITestStateNonce, deviceUINow.Add(time.Minute).Unix(), wrongKey),
		},
		{
			"payload not base64",
			"!!!." + base64.RawURLEncoding.EncodeToString(hmacOf(s.key, []byte("anything"))),
		},
		{
			"mac not base64",
			base64.RawURLEncoding.EncodeToString(validPayload(deviceUITestUserCanonical, deviceUINow.Add(time.Minute).Unix())) + ".!!!",
		},
		{
			"payload not JSON",
			func() string {
				raw := []byte("not-json-at-all")
				return base64.RawURLEncoding.EncodeToString(raw) + "." +
					base64.RawURLEncoding.EncodeToString(hmacOf(s.key, raw))
			}(),
		},
		{
			"empty user_code",
			func() string {
				raw := validPayload("", deviceUINow.Add(time.Minute).Unix())
				return base64.RawURLEncoding.EncodeToString(raw) + "." +
					base64.RawURLEncoding.EncodeToString(hmacOf(s.key, raw))
			}(),
		},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			resp, err := s.client.Get(s.srv.URL + "/device/sso-callback?code=auth-code&state=" + url.QueryEscape(tc.state))
			s.Require().NoError(err)
			defer resp.Body.Close()
			s.Equal(http.StatusOK, resp.StatusCode)
			s.Contains(readBody(s.T(), resp), "could not be completed")
		})
	}
}

// TestDecisionStoreErrorIs500 covers the non-sentinel error branch out of
// ApproveDeviceCode / DenyDeviceCode: a deep store failure surfaces as a
// 5xx, not a 200 error page, so an operator's monitoring sees it.
func (s *DeviceUISuite) TestDecisionStoreErrorIs500() {
	cookieValue := s.seedSession()
	s.store.approveErr = errors.New("disk fell off")

	r := s.post("/device/approve",
		url.Values{"csrf_token": {deviceUITestSID}, "user_code": {deviceUITestUserDisplay}})
	r.Header.Set("Cookie", cookieValue)
	resp, err := s.client.Do(r)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusInternalServerError, resp.StatusCode)
}

// TestTemplatesEmitNoExternalAssets pins the CSP-tight contract: no
// rendered page may reference an external stylesheet or script — the
// templates are self-contained so a Content-Security-Policy that forbids
// external loads doesn't break the page.
func (s *DeviceUISuite) TestTemplatesEmitNoExternalAssets() {
	cookieValue := s.seedSession()

	// Render the confirm page (most chrome).
	r := s.req(http.MethodGet, "/device/confirm?user_code="+deviceUITestUserDisplay)
	r.Header.Set("Cookie", cookieValue)
	resp, err := s.client.Do(r)
	s.Require().NoError(err)
	defer resp.Body.Close()

	body := readBody(s.T(), resp)
	s.NotContains(body, `<link rel="stylesheet"`)
	s.NotContains(body, `<script src=`)
	s.NotContains(body, `https://`, "no external resource URLs may appear in the rendered page")
}

func TestNewDeviceUIRejectsMissingInternalClient(t *testing.T) {
	reg, err := oidc.ParseClientRegistry("tempogate-device:cli")
	if err != nil {
		t.Fatalf("parse clients: %v", err)
	}
	sm := oidc.NewSessionManager(newMemBrowserSessionStore(), []byte("0123456789abcdef0123456789abcdef"))
	_, err = oidc.NewDeviceUI(&memDeviceCodeStore{}, sm, reg, newFakeAuthCodeRedeemer(""), []byte("0123456789abcdef0123456789abcdef"), testIssuer)
	if !errors.Is(err, oidc.ErrInternalDeviceUIClientMissing) {
		t.Fatalf("expected ErrInternalDeviceUIClientMissing, got %v", err)
	}
}

func TestNewDeviceUIRejectsPublicInternalClient(t *testing.T) {
	reg, err := oidc.ParseClientRegistry(deviceUIClientsRaw)
	if err != nil {
		t.Fatalf("parse clients: %v", err)
	}
	// Skip WithSecrets — the device-ui client stays public, which is the
	// misconfiguration this asserts is caught.
	sm := oidc.NewSessionManager(newMemBrowserSessionStore(), []byte("0123456789abcdef0123456789abcdef"))
	_, err = oidc.NewDeviceUI(&memDeviceCodeStore{}, sm, reg, newFakeAuthCodeRedeemer(""), []byte("0123456789abcdef0123456789abcdef"), testIssuer)
	if !errors.Is(err, oidc.ErrInternalDeviceUIClientNotConfidential) {
		t.Fatalf("expected ErrInternalDeviceUIClientNotConfidential, got %v", err)
	}
}

// TestNewDeviceUIRejectsNilRedeemer pins the fail-fast on the new
// dependency: a nil AuthCodeRedeemer would surface as a nil-pointer panic
// at the first SSO callback otherwise. Both the untyped nil and a
// typed-nil interface value (the wiring-bug shape that `redeemer == nil`
// alone would miss because the interface still carries type info) must
// reject at construction.
func TestNewDeviceUIRejectsNilRedeemer(t *testing.T) {
	reg, err := oidc.ParseClientRegistry(deviceUIClientsRaw)
	if err != nil {
		t.Fatalf("parse clients: %v", err)
	}
	if err := reg.WithSecrets("tempogate-device-ui:" + deviceUIInternalSecret); err != nil {
		t.Fatalf("with secrets: %v", err)
	}
	sm := oidc.NewSessionManager(newMemBrowserSessionStore(), []byte("0123456789abcdef0123456789abcdef"))

	cases := []struct {
		name     string
		redeemer oidc.AuthCodeRedeemer
	}{
		{"untyped nil", nil},
		{"typed nil pointer", (*fakeAuthCodeRedeemer)(nil)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := oidc.NewDeviceUI(&memDeviceCodeStore{}, sm, reg, tc.redeemer, []byte("0123456789abcdef0123456789abcdef"), testIssuer)
			if !errors.Is(err, oidc.ErrNilAuthCodeRedeemer) {
				t.Fatalf("expected ErrNilAuthCodeRedeemer, got %v", err)
			}
		})
	}
}

// TestEnterPageCSPIncludesUpstreamFormActionSource pins the regression:
// CSP3 §6.7.2.5 enforces form-action against every URL in the redirect
// chain that follows a form submission, so an upstream IdP on a different
// origin from the issuer (every production Google deployment) needs its
// origin in the directive's source list or the browser silently refuses
// the cross-origin hop. The handler must surface the upstream origin into
// the rendered CSP alongside 'self'.
func (s *DeviceUISuite) TestEnterPageCSPIncludesUpstreamFormActionSource() {
	ui, err := oidc.NewDeviceUI(s.store, s.sessions, s.clients, s.redeemer, s.key, testIssuer,
		oidc.WithDeviceUIClock(func() time.Time { return deviceUINow }),
		oidc.WithUpstreamIDPOrigin("https://accounts.google.com/o/oauth2/v2/auth"),
	)
	s.Require().NoError(err)
	mux := http.NewServeMux()
	ui.Register(humago.New(mux, huma.DefaultConfig("device-ui-csp-enter", "0.0.0")))
	local := httptest.NewServer(mux)
	defer local.Close()

	resp, err := s.client.Get(local.URL + "/device")
	s.Require().NoError(err)
	defer resp.Body.Close()
	body := readBody(s.T(), resp)
	s.Contains(body, "form-action 'self' https://accounts.google.com;",
		"device_enter CSP must whitelist the upstream IdP origin alongside 'self'")
}

// TestEnterPageCSPDefaultsToSelfWithoutUpstream covers the back-compat
// posture: the suite's existing DeviceUI does not set WithUpstreamIDPOrigin,
// so its entry page must keep form-action at 'self' with no trailing junk.
// Deployments whose upstream IdP shares the issuer's origin (typical for
// in-process integration tests) rely on this.
func (s *DeviceUISuite) TestEnterPageCSPDefaultsToSelfWithoutUpstream() {
	resp, err := s.client.Do(s.req(http.MethodGet, "/device"))
	s.Require().NoError(err)
	defer resp.Body.Close()
	body := readBody(s.T(), resp)
	s.Contains(body, "form-action 'self';",
		"entry page form-action must default to 'self' when no upstream origin is wired")
	s.NotContains(body, "form-action 'self' ",
		"no trailing source should leak in when upstream is unset")
}

// TestConfirmPageCSPStaysAtSelf asserts the post-SSO pages keep the
// tighter form-action 'self' directive even when the device-ui is wired
// with an upstream origin: their Approve/Deny POSTs are same-origin, so
// widening the directive there would be a needless loss of defense-in-
// depth.
func (s *DeviceUISuite) TestConfirmPageCSPStaysAtSelf() {
	ui, err := oidc.NewDeviceUI(s.store, s.sessions, s.clients, s.redeemer, s.key, testIssuer,
		oidc.WithDeviceUIClock(func() time.Time { return deviceUINow }),
		oidc.WithUpstreamIDPOrigin("https://accounts.google.com/o/oauth2/v2/auth"),
	)
	s.Require().NoError(err)
	mux := http.NewServeMux()
	ui.Register(humago.New(mux, huma.DefaultConfig("device-ui-csp-confirm", "0.0.0")))
	local := httptest.NewServer(mux)
	defer local.Close()

	cookieValue := s.seedSession()
	req, err := http.NewRequest(http.MethodGet, local.URL+"/device/confirm?user_code="+deviceUITestUserDisplay, http.NoBody)
	s.Require().NoError(err)
	req.Header.Set("Cookie", cookieValue)
	resp, err := s.client.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode)
	body := readBody(s.T(), resp)
	s.Contains(body, "form-action 'self';",
		"confirm page form-action must stay at 'self' — its POSTs are same-origin")
	s.NotContains(body, "accounts.google.com",
		"upstream origin must not leak into post-SSO pages")
}

// TestNewDeviceUIRejectsInvalidUpstreamOrigin pins the parser's failure
// modes: a non-empty raw value must be an absolute URL with scheme +
// host, and the scheme must be http or https (the CSP source grammar
// doesn't accept other schemes for form-action anyway).
func TestNewDeviceUIRejectsInvalidUpstreamOrigin(t *testing.T) {
	reg, err := oidc.ParseClientRegistry(deviceUIClientsRaw)
	if err != nil {
		t.Fatalf("parse clients: %v", err)
	}
	if err := reg.WithSecrets("tempogate-device-ui:" + deviceUIInternalSecret); err != nil {
		t.Fatalf("with secrets: %v", err)
	}
	sm := oidc.NewSessionManager(newMemBrowserSessionStore(), []byte("0123456789abcdef0123456789abcdef"))
	key := []byte("0123456789abcdef0123456789abcdef")

	cases := []struct {
		name string
		raw  string
	}{
		{"no scheme", "accounts.google.com/o/oauth2/v2/auth"},
		{"no host", "https:///oauth2/v2/auth"},
		{"file scheme", "file:///oauth2/auth"},
		{"unparseable", "://broken"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := oidc.NewDeviceUI(&memDeviceCodeStore{}, sm, reg, newFakeAuthCodeRedeemer(""), key, testIssuer,
				oidc.WithUpstreamIDPOrigin(tc.raw))
			if !errors.Is(err, oidc.ErrInvalidUpstreamIDPOrigin) {
				t.Fatalf("expected ErrInvalidUpstreamIDPOrigin for %q, got %v", tc.raw, err)
			}
		})
	}
}

// TestNewDeviceUIUpstreamOriginVariants pins the accepted shapes: an
// authorization-endpoint URL with a path, query, port, or upper-case
// scheme collapses to the canonical "scheme://host[:port]" CSP source.
// Empty is permitted (back-compat for same-origin upstream test setups).
func TestNewDeviceUIUpstreamOriginVariants(t *testing.T) {
	reg, err := oidc.ParseClientRegistry(deviceUIClientsRaw)
	if err != nil {
		t.Fatalf("parse clients: %v", err)
	}
	if err := reg.WithSecrets("tempogate-device-ui:" + deviceUIInternalSecret); err != nil {
		t.Fatalf("with secrets: %v", err)
	}
	sm := oidc.NewSessionManager(newMemBrowserSessionStore(), []byte("0123456789abcdef0123456789abcdef"))
	key := []byte("0123456789abcdef0123456789abcdef")

	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"https with path", "https://accounts.google.com/o/oauth2/v2/auth", "https://accounts.google.com"},
		{"https with port + query", "https://idp.example.com:8443/auth?x=1", "https://idp.example.com:8443"},
		{"http loopback", "http://127.0.0.1:5556/dex/auth", "http://127.0.0.1:5556"},
		{"upper-case scheme", "HTTPS://idp.example.com/auth", "https://idp.example.com"},
		{"empty (back-compat)", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ui, err := oidc.NewDeviceUI(&memDeviceCodeStore{}, sm, reg, newFakeAuthCodeRedeemer(""), key, testIssuer,
				oidc.WithUpstreamIDPOrigin(tc.raw))
			if err != nil {
				t.Fatalf("construct: %v", err)
			}
			mux := http.NewServeMux()
			ui.Register(humago.New(mux, huma.DefaultConfig("device-ui-variants", "0.0.0")))
			srv := httptest.NewServer(mux)
			defer srv.Close()

			resp, err := http.Get(srv.URL + "/device") //nolint:noctx // test-only loopback
			if err != nil {
				t.Fatalf("get: %v", err)
			}
			b, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			body := string(b)
			wantSubstring := "form-action 'self';"
			if tc.want != "" {
				wantSubstring = "form-action 'self' " + tc.want + ";"
			}
			if !strings.Contains(body, wantSubstring) {
				t.Fatalf("expected %q in rendered CSP, got: %s", wantSubstring, formActionSlice(body))
			}
		})
	}
}

// formActionSlice extracts the form-action directive substring (up to the
// next ';') so test failure messages stay readable instead of dumping the
// entire <head> CSP meta tag.
func formActionSlice(body string) string {
	i := strings.Index(body, "form-action ")
	if i < 0 {
		return "(no form-action in body)"
	}
	tail := body[i:]
	if j := strings.Index(tail, ";"); j >= 0 {
		return tail[:j]
	}
	return tail
}

func TestNewDeviceUIAcceptsCustomInternalClientID(t *testing.T) {
	reg, err := oidc.ParseClientRegistry("tempogate-device:cli,my-custom-ui:" + testIssuer + "/device/sso-callback")
	if err != nil {
		t.Fatalf("parse clients: %v", err)
	}
	if err := reg.WithSecrets("my-custom-ui:" + deviceUIInternalSecret); err != nil {
		t.Fatalf("with secrets: %v", err)
	}
	sm := oidc.NewSessionManager(newMemBrowserSessionStore(), []byte("0123456789abcdef0123456789abcdef"))
	_, err = oidc.NewDeviceUI(&memDeviceCodeStore{}, sm, reg, newFakeAuthCodeRedeemer(""), []byte("0123456789abcdef0123456789abcdef"), testIssuer,
		oidc.WithInternalClientID("my-custom-ui"))
	if err != nil {
		t.Fatalf("custom client id should be honoured: %v", err)
	}
}

// signedBounceState mirrors the production state-signing path with the
// suite's signing key, so tests forge a state value that the DeviceUI
// accepts without exporting the internal signing helper.
func (s *DeviceUISuite) signedBounceState(canonical, nonce string, exp int64) string {
	return signedBounceStateWithKey(canonical, nonce, exp, s.key)
}

func signedBounceStateWithKey(canonical, nonce string, exp int64, key []byte) string {
	payload, _ := json.Marshal(struct {
		UserCode string `json:"user_code"`
		Nonce    string `json:"nonce"`
		Exp      int64  `json:"exp"`
	}{UserCode: canonical, Nonce: nonce, Exp: exp})
	mac := hmacOf(key, payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(mac)
}

func hmacOf(key, payload []byte) []byte {
	h := stdHMACSHA256(key)
	_, _ = h.Write(payload)
	return h.Sum(nil)
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}

// TestSSOCallbackCompletesWhenIssuerHostIsUnreachable is the load-bearing
// guard on this package's promise that auth-code redemption does not
// reach back through the issuer URL. The DeviceUI here is wired with an
// issuer whose host is reserved-unresolvable by RFC 2606 (".invalid"
// TLD); the auth code is seeded directly into an in-memory TokenStore,
// and a real *Token consumes it in-process. If a future edit
// reintroduces any kind of HTTP round-trip back through the issuer for
// redemption, the call would fault on DNS resolution and the callback
// would render the generic error page instead of the 303 to /device/confirm.
func TestSSOCallbackCompletesWhenIssuerHostIsUnreachable(t *testing.T) {
	const (
		unreachableIssuer = "https://no-such-host.invalid/idp"
		callbackPath      = "/device/sso-callback"
		userCanonical     = "BCDFGHJK"
		userDisplay       = "BCDF-GHJK"
		stateNonce        = "fixed-state-nonce"
		authCode          = "in-process-auth-code"
		email             = "alice@example.com"
		internalSecret    = "device-ui-secret"
	)
	now := time.Unix(1700000000, 0).UTC()
	signingKey := []byte("0123456789abcdef0123456789abcdef")

	reg, err := oidc.ParseClientRegistry("tempogate-device:cli,tempogate-device-ui:" + unreachableIssuer + callbackPath)
	if err != nil {
		t.Fatalf("parse clients: %v", err)
	}
	if err := reg.WithSecrets("tempogate-device-ui:" + internalSecret); err != nil {
		t.Fatalf("with secrets: %v", err)
	}

	tokenStore := newMemTokenStore()
	tokenStore.putCode(oidc.AuthCode{
		Code:        authCode,
		ClientID:    "tempogate-device-ui",
		RedirectURI: unreachableIssuer + callbackPath,
		Email:       email,
		Scope:       "openid email",
		CreatedAt:   now,
		ExpiresAt:   now.Add(time.Minute),
	})

	// nil signer is safe here: RedeemAuthorizationCode returns the
	// consumed AuthCode's claims before any token minting, so the signer
	// is never dereferenced on this code path. The public /token handler
	// would dereference it via t.issue, which this test does not exercise.
	token := oidc.NewToken(tokenStore, nil, reg, oidc.WithTokenClock(func() time.Time { return now }))

	bsStore := newMemBrowserSessionStore()
	sessions := oidc.NewSessionManager(bsStore, signingKey,
		oidc.WithSessionClock(func() time.Time { return now }),
		oidc.WithSessionTTL(5*time.Minute),
		oidc.WithSessionSIDGenerator(func() (string, error) { return "fixed-sid", nil }),
	)

	devices := newStatefulDeviceCodeStore()
	devices.put(oidc.DeviceCode{
		Code:            "fixed-device-code",
		UserCode:        userCanonical,
		ClientID:        "tempogate-device",
		IntervalSeconds: 5,
		CreatedAt:       now,
		ExpiresAt:       now.Add(15 * time.Minute),
	})

	ui, err := oidc.NewDeviceUI(devices, sessions, reg, token, signingKey, unreachableIssuer,
		oidc.WithDeviceUIClock(func() time.Time { return now }),
		oidc.WithDeviceUIStateNonceGenerator(func() (string, error) { return stateNonce, nil }),
	)
	if err != nil {
		t.Fatalf("construct device-ui: %v", err)
	}

	mux := http.NewServeMux()
	ui.Register(humago.New(mux, huma.DefaultConfig("device-ui-unreachable-issuer", "0.0.0")))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	state := signedBounceStateWithKey(userCanonical, stateNonce, now.Add(time.Minute).Unix(), signingKey)
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequest(http.MethodGet, srv.URL+callbackPath+"?code="+authCode+"&state="+url.QueryEscape(state), http.NoBody)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("sso callback request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect on successful in-process redemption; got %d, body: %s",
			resp.StatusCode, readBody(t, resp))
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect Location: %v", err)
	}
	// The redirect carries the issuer's path prefix ("/idp" here) because
	// the device-ui mounts under whatever public base path the issuer
	// advertises — the confirm path is the one this issuer would publish,
	// not the bare /device/confirm.
	if loc.Path != "/idp/device/confirm" {
		t.Fatalf("expected redirect to /idp/device/confirm; got %q", loc.Path)
	}
	if got := loc.Query().Get("user_code"); got != userDisplay {
		t.Fatalf("expected user_code=%q in redirect query; got %q", userDisplay, got)
	}
	if got := bsStore.count(); got != 1 {
		t.Fatalf("expected exactly one browser session minted; got %d", got)
	}
	if got := bsStore.only().Email; got != email {
		t.Fatalf("expected session email=%q; got %q", email, got)
	}
}
