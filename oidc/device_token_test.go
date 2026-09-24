package oidc_test

import (
	"context"
	"encoding/json"
	"net/url"
	"sync"
	"time"

	jwxjwt "github.com/lestrrat-go/jwx/v4/jwt"

	"github.com/onhotpath/tempogate/oidc"
)

// memDeviceFlowStore is a fully-stateful in-memory oidc.DeviceCodeStore for
// the /token device-code-grant tests. It is intentionally separate from the
// /device_authorization tests' memDeviceCodeStore (whose downstream methods
// are stubbed to surface contract drift on the issuance side); here we want
// the opposite property — every method behaves like the sqlite store so the
// handler's branching can be exercised against a realistic backend.
type memDeviceFlowStore struct {
	mu     sync.Mutex
	rows   map[string]oidc.DeviceCode
	byUser map[string]string // user_code → device_code

	touchErr   error
	consumeErr error
}

func newMemDeviceFlowStore() *memDeviceFlowStore {
	return &memDeviceFlowStore{
		rows:   map[string]oidc.DeviceCode{},
		byUser: map[string]string{},
	}
}

func (m *memDeviceFlowStore) put(dc oidc.DeviceCode) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rows[dc.Code] = dc
	if dc.UserCode != "" {
		m.byUser[dc.UserCode] = dc.Code
	}
}

func (m *memDeviceFlowStore) get(deviceCode string) (oidc.DeviceCode, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	dc, ok := m.rows[deviceCode]
	return dc, ok
}

func (m *memDeviceFlowStore) SaveDeviceCode(_ context.Context, dc oidc.DeviceCode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.rows[dc.Code]; exists {
		return oidc.ErrDuplicateDeviceCode
	}
	if _, exists := m.byUser[dc.UserCode]; exists {
		return oidc.ErrDuplicateDeviceCode
	}
	m.rows[dc.Code] = dc
	m.byUser[dc.UserCode] = dc.Code
	return nil
}

func (m *memDeviceFlowStore) LookupDeviceCodeByDeviceCode(_ context.Context, deviceCode string) (oidc.DeviceCode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	dc, ok := m.rows[deviceCode]
	if !ok {
		return oidc.DeviceCode{}, oidc.ErrDeviceCodeNotFound
	}
	return dc, nil
}

func (m *memDeviceFlowStore) LookupDeviceCodeByUserCode(_ context.Context, userCode string) (oidc.DeviceCode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	dcCode, ok := m.byUser[userCode]
	if !ok {
		return oidc.DeviceCode{}, oidc.ErrDeviceCodeNotFound
	}
	return m.rows[dcCode], nil
}

func (m *memDeviceFlowStore) TouchDeviceCodePoll(_ context.Context, deviceCode string, now time.Time, bumpInterval bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.touchErr != nil {
		return m.touchErr
	}
	dc, ok := m.rows[deviceCode]
	if !ok {
		return oidc.ErrDeviceCodeNotFound
	}
	t := now
	dc.LastPolledAt = &t
	if bumpInterval {
		dc.IntervalSeconds += 5
	}
	m.rows[deviceCode] = dc
	return nil
}

func (m *memDeviceFlowStore) ApproveDeviceCode(_ context.Context, userCode, email string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	dcCode, ok := m.byUser[userCode]
	if !ok {
		return oidc.ErrDeviceCodeNotPending
	}
	dc := m.rows[dcCode]
	if dc.ApprovedAt != nil || dc.DeniedAt != nil {
		return oidc.ErrDeviceCodeNotPending
	}
	t := now
	dc.ApprovedAt = &t
	dc.Email = email
	m.rows[dcCode] = dc
	return nil
}

func (m *memDeviceFlowStore) DenyDeviceCode(_ context.Context, userCode string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	dcCode, ok := m.byUser[userCode]
	if !ok {
		return oidc.ErrDeviceCodeNotPending
	}
	dc := m.rows[dcCode]
	if dc.ApprovedAt != nil || dc.DeniedAt != nil {
		return oidc.ErrDeviceCodeNotPending
	}
	t := now
	dc.DeniedAt = &t
	m.rows[dcCode] = dc
	return nil
}

func (m *memDeviceFlowStore) ConsumeDeviceCode(_ context.Context, deviceCode string) (oidc.DeviceCode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.consumeErr != nil {
		return oidc.DeviceCode{}, m.consumeErr
	}
	dc, ok := m.rows[deviceCode]
	if !ok {
		return oidc.DeviceCode{}, oidc.ErrDeviceCodeNotFound
	}
	delete(m.rows, deviceCode)
	delete(m.byUser, dc.UserCode)
	return dc, nil
}

const grantDeviceCode = "urn:ietf:params:oauth:grant-type:device_code"

// pendingDeviceCode returns a freshly-issued, still-pending device_code row
// stamped at signNow with the default 5-second interval and a 15-minute TTL.
// Tests use it as a base and mutate fields to model the various RFC 8628 §3.5
// branches.
func pendingDeviceCode(deviceCode, userCode string) oidc.DeviceCode {
	return oidc.DeviceCode{
		Code:            deviceCode,
		UserCode:        userCode,
		ClientID:        "tempogate-device",
		Scope:           "openid email",
		IntervalSeconds: 5,
		CreatedAt:       signNow,
		ExpiresAt:       signNow.Add(15 * time.Minute),
	}
}

// deviceForm builds the form body the CLI sends on every poll: the device_code
// grant token-endpoint contract.
func deviceForm(deviceCode, clientID string) url.Values {
	f := url.Values{}
	f.Set("grant_type", grantDeviceCode)
	if deviceCode != "" {
		f.Set("device_code", deviceCode)
	}
	if clientID != "" {
		f.Set("client_id", clientID)
	}
	// Keep the body non-empty even when both fields are dropped, so the form
	// parser never short-circuits on "no parameters" before the handler can
	// emit its own invalid_request.
	f.Set("filler", "x")
	return f
}

func (s *TokenSuite) seedPending(deviceCode, userCode string) {
	s.deviceStore.put(pendingDeviceCode(deviceCode, userCode))
}

func (s *TokenSuite) approve(userCode, email string) {
	s.Require().NoError(s.deviceStore.ApproveDeviceCode(context.Background(), userCode, email, signNow))
}

func (s *TokenSuite) deny(userCode string) {
	s.Require().NoError(s.deviceStore.DenyDeviceCode(context.Background(), userCode, signNow))
}

func (s *TokenSuite) TestDeviceCodeGrantMissingFields() {
	cases := []struct {
		name     string
		drop     string
		wantCode string
	}{
		{"missing device_code", "device_code", "invalid_request"},
		{"missing client_id", "client_id", "invalid_request"},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			f := deviceForm("dc-1", "tempogate-device")
			f.Del(tc.drop)
			resp := s.post(f)
			defer resp.Body.Close()
			s.Equal(400, resp.StatusCode)
			s.Equal(tc.wantCode, s.decodeOAuthError(resp))
		})
	}
}

func (s *TokenSuite) TestDeviceCodeUnknownIsInvalidGrant() {
	resp := s.post(deviceForm("never-issued", "tempogate-device"))
	defer resp.Body.Close()
	s.Equal(400, resp.StatusCode)
	s.Equal("invalid_grant", s.decodeOAuthError(resp))
}

func (s *TokenSuite) TestDeviceCodeClientIDMismatchIsInvalidClient() {
	s.seedPending("dc-1", "BCDFGHJK")

	resp := s.post(deviceForm("dc-1", "someone-else"))
	defer resp.Body.Close()
	s.Equal(401, resp.StatusCode)
	s.Equal("invalid_client", s.decodeOAuthError(resp))
}

func (s *TokenSuite) TestDeviceCodeAuthorizationPending() {
	s.seedPending("dc-1", "BCDFGHJK")

	resp := s.post(deviceForm("dc-1", "tempogate-device"))
	defer resp.Body.Close()
	s.Equal(400, resp.StatusCode)
	s.Equal("authorization_pending", s.decodeOAuthError(resp))

	// LastPolledAt is now stamped but the interval was not bumped: the first
	// poll is not "too fast" by definition.
	dc, ok := s.deviceStore.get("dc-1")
	s.Require().True(ok, "row must still exist after authorization_pending")
	s.Require().NotNil(dc.LastPolledAt)
	s.Equal(5, dc.IntervalSeconds, "first poll never bumps the interval")
}

// TestDeviceCodeSlowDownBumpsInterval is the slow_down invariant in
// acceptance criteria: every poll inside the current interval window returns
// slow_down AND raises the stored interval by +5s, so successive too-fast
// polls keep ratcheting the floor up.
func (s *TokenSuite) TestDeviceCodeSlowDownBumpsInterval() {
	s.seedPending("dc-1", "BCDFGHJK")

	// First poll: spaces out far enough; returns authorization_pending and
	// stamps last_polled_at without bumping.
	first := s.post(deviceForm("dc-1", "tempogate-device"))
	s.Require().Equal(400, first.StatusCode)
	s.Equal("authorization_pending", s.decodeOAuthError(first))
	first.Body.Close()

	// Second poll: same instant as the first ⇒ inside the 5s interval ⇒
	// slow_down, and the interval becomes 10.
	second := s.post(deviceForm("dc-1", "tempogate-device"))
	s.Equal(400, second.StatusCode)
	s.Equal("slow_down", s.decodeOAuthError(second))
	second.Body.Close()

	dc, _ := s.deviceStore.get("dc-1")
	s.Equal(10, dc.IntervalSeconds, "first slow_down bumps 5 → 10")

	// Third poll: still inside the (now 10s) window ⇒ slow_down again, 10 → 15.
	third := s.post(deviceForm("dc-1", "tempogate-device"))
	s.Equal(400, third.StatusCode)
	s.Equal("slow_down", s.decodeOAuthError(third))
	third.Body.Close()

	dc, _ = s.deviceStore.get("dc-1")
	s.Equal(15, dc.IntervalSeconds, "successive slow_downs keep ratcheting +5")
}

// TestDeviceCodeWellBehavedPollDoesNotBump is the complement: a poll that
// arrives after the interval window passes never bumps, even on the path that
// returns authorization_pending.
func (s *TokenSuite) TestDeviceCodeWellBehavedPollDoesNotBump() {
	s.seedPending("dc-1", "BCDFGHJK")

	// Manually stamp a last_polled_at well in the past so the next poll is
	// safely outside the 5s window.
	dc, _ := s.deviceStore.get("dc-1")
	past := signNow.Add(-time.Minute)
	dc.LastPolledAt = &past
	s.deviceStore.put(dc)

	resp := s.post(deviceForm("dc-1", "tempogate-device"))
	defer resp.Body.Close()
	s.Equal(400, resp.StatusCode)
	s.Equal("authorization_pending", s.decodeOAuthError(resp))

	dc, _ = s.deviceStore.get("dc-1")
	s.Equal(5, dc.IntervalSeconds, "a properly-paced poll never bumps")
}

// TestDeviceCodeExpiredSelfConsumes is the expiry invariant: the first poll
// that observes the expired row consumes it, so a follow-up poll returns the
// generic invalid_grant rather than expired_token a second time.
func (s *TokenSuite) TestDeviceCodeExpiredSelfConsumes() {
	dc := pendingDeviceCode("dc-1", "BCDFGHJK")
	dc.ExpiresAt = signNow.Add(-time.Second)
	s.deviceStore.put(dc)

	first := s.post(deviceForm("dc-1", "tempogate-device"))
	s.Equal(400, first.StatusCode)
	s.Equal("expired_token", s.decodeOAuthError(first))
	first.Body.Close()

	_, stillExists := s.deviceStore.get("dc-1")
	s.False(stillExists, "expired row must be consumed on the first observing poll")

	second := s.post(deviceForm("dc-1", "tempogate-device"))
	defer second.Body.Close()
	s.Equal(400, second.StatusCode)
	s.Equal("invalid_grant", s.decodeOAuthError(second))
}

// TestDeviceCodeDeniedSelfConsumes: same invariant, denied branch.
func (s *TokenSuite) TestDeviceCodeDeniedSelfConsumes() {
	s.seedPending("dc-1", "BCDFGHJK")
	s.deny("BCDFGHJK")

	first := s.post(deviceForm("dc-1", "tempogate-device"))
	s.Equal(400, first.StatusCode)
	s.Equal("access_denied", s.decodeOAuthError(first))
	first.Body.Close()

	_, stillExists := s.deviceStore.get("dc-1")
	s.False(stillExists, "denied row must be consumed on the first observing poll")

	second := s.post(deviceForm("dc-1", "tempogate-device"))
	defer second.Body.Close()
	s.Equal(400, second.StatusCode)
	s.Equal("invalid_grant", s.decodeOAuthError(second))
}

// TestDeviceCodeApprovedMintsTokenAndConsumes is the happy path: Approve has
// stamped the row; the poll consumes it and mints a Token whose shape matches
// the authorization_code path (same claims, same TTL, no nonce).
func (s *TokenSuite) TestDeviceCodeApprovedMintsTokenAndConsumes() {
	s.seedPending("dc-1", "BCDFGHJK")
	s.approve("BCDFGHJK", "alice@example.com")

	resp := s.post(deviceForm("dc-1", "tempogate-device"))
	defer resp.Body.Close()
	s.Require().Equal(200, resp.StatusCode)
	s.Equal("no-store", resp.Header.Get("Cache-Control"))
	s.Equal("no-cache", resp.Header.Get("Pragma"))

	body := s.decodeTokenResponse(resp)
	s.Equal("Bearer", body.TokenType)
	s.Equal(14400, body.ExpiresIn)
	s.Equal(fixedRefresh, body.RefreshToken)
	s.Equal(body.AccessToken, body.IDToken)

	tok, err := s.verifier.Verify(context.Background(), body.AccessToken)
	s.Require().NoError(err)
	sub, _ := tok.Subject()
	s.Equal("alice@example.com", sub)
	aud, _ := tok.Audience()
	s.Equal([]string{"tempogate-device"}, aud, "aud must echo the polling client_id")
	perms, ok := tok.Field("permissions")
	s.Require().True(ok)
	s.Equal([]string{"temporal-system:admin"}, toStringSlice(s.T(), perms))

	// RFC 8628 has no nonce concept — the device-flow path must never stamp
	// one. (jwx returns false when the claim is absent.)
	_, hasNonce := tok.Field("nonce")
	s.False(hasNonce, "device-code flow has no nonce")

	exp, _ := tok.Expiration()
	s.True(exp.Equal(signNow.Add(4*time.Hour)), "device-code TTL must match authorization_code TTL")

	// Row consumed: a second poll returns invalid_grant.
	_, stillExists := s.deviceStore.get("dc-1")
	s.False(stillExists)

	second := s.post(deviceForm("dc-1", "tempogate-device"))
	defer second.Body.Close()
	s.Equal(400, second.StatusCode)
	s.Equal("invalid_grant", s.decodeOAuthError(second))
}

// TestDeviceCodeClaimsMatchAuthorizationCode is the byte-identical-claims
// criterion: the same email + client_id minted through either grant must
// produce the same sub/email/aud/permissions/TTL. (jti, iat, exp drift per
// mint; nonce is deliberately absent on the device path.)
func (s *TokenSuite) TestDeviceCodeClaimsMatchAuthorizationCode() {
	// authorization_code path with empty nonce (no rp-nonce in the auth code).
	ac := s.authCode("code-1")
	ac.Nonce = ""
	ac.ClientID = "tempogate-device"
	s.store.putCode(ac)

	f := authCodeForm()
	f.Set("client_id", "tempogate-device")
	acResp := s.post(f)
	s.Require().Equal(200, acResp.StatusCode)
	acTok, err := s.verifier.Verify(context.Background(), s.decodeTokenResponse(acResp).AccessToken)
	acResp.Body.Close()
	s.Require().NoError(err)

	// device_code path with the same email + client_id.
	s.seedPending("dc-1", "BCDFGHJK")
	s.approve("BCDFGHJK", "alice@example.com")
	dcResp := s.post(deviceForm("dc-1", "tempogate-device"))
	defer dcResp.Body.Close()
	s.Require().Equal(200, dcResp.StatusCode)
	dcTok, err := s.verifier.Verify(context.Background(), s.decodeTokenResponse(dcResp).AccessToken)
	s.Require().NoError(err)

	acSub, _ := acTok.Subject()
	dcSub, _ := dcTok.Subject()
	s.Equal(acSub, dcSub)

	acEmail, _ := jwxjwt.Get[string](acTok, "email")
	dcEmail, _ := jwxjwt.Get[string](dcTok, "email")
	s.Equal(acEmail, dcEmail)

	acAud, _ := acTok.Audience()
	dcAud, _ := dcTok.Audience()
	s.Equal(acAud, dcAud)

	acPerms, _ := acTok.Field("permissions")
	dcPerms, _ := dcTok.Field("permissions")
	s.Equal(toStringSlice(s.T(), acPerms), toStringSlice(s.T(), dcPerms))

	acExp, _ := acTok.Expiration()
	acIat, _ := acTok.IssuedAt()
	dcExp, _ := dcTok.Expiration()
	dcIat, _ := dcTok.IssuedAt()
	s.Equal(acExp.Sub(acIat), dcExp.Sub(dcIat), "TTL must be identical across grants")

	_, hasNonce := dcTok.Field("nonce")
	s.False(hasNonce, "device-code token must carry no nonce")
}

// TestUnsupportedGrantTypeListsDeviceCode is a small regression on the
// dispatch error wording: now that device_code is supported, the
// unsupported_grant_type description must list it alongside the other two so
// CLI users see a self-documenting error.
func (s *TokenSuite) TestUnsupportedGrantTypeListsDeviceCode() {
	f := url.Values{}
	f.Set("grant_type", "client_credentials")
	f.Set("filler", "x")
	resp := s.post(f)
	defer resp.Body.Close()
	s.Equal(400, resp.StatusCode)

	var body struct {
		Error string `json:"error"`
		Desc  string `json:"error_description"`
	}
	s.Require().NoError(json.NewDecoder(resp.Body).Decode(&body))
	s.Equal("unsupported_grant_type", body.Error)
	s.Contains(body.Desc, "device_code", "error_description must enumerate device_code now that it is supported")
}
