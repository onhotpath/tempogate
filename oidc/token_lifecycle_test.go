package oidc_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

	"github.com/onhotpath/tempogate/keys"
	"github.com/onhotpath/tempogate/oidc"
)

// Lifetimes small enough to walk with a fake clock and distinct enough that
// each limit is the one that trips: idle (24h) < absolute (72h).
const (
	lcAccessTTL  = time.Hour
	lcRefreshTTL = 24 * time.Hour
	lcMaxLife    = 72 * time.Hour
)

// RefreshLifecycleSuite covers H2 and M3: the absolute session lifetime,
// the idle lifetime, the domain re-check, and reuse detection with family
// revocation, all driven through POST /token with a movable clock.
type RefreshLifecycleSuite struct {
	suite.Suite

	store   *memTokenStore
	signer  *keys.Signer
	clients oidc.ClientRegistry
	logs    *bytes.Buffer
	srv     *httptest.Server
	client  *http.Client

	// defaultLifetimes serves /token without WithTokenLifetimes, so the
	// package defaults apply.
	defaultLifetimes bool

	mu  sync.Mutex
	now time.Time
	seq int
}

func TestRefreshLifecycleSuite(t *testing.T) {
	suite.Run(t, new(RefreshLifecycleSuite))
}

func (s *RefreshLifecycleSuite) SetupTest() {
	ks := &memKeyStore{}
	k := keys.New(keys.WithStore(ks), keys.WithGenerateOptions(keys.WithRSABits(2048)))
	s.Require().NoError(k.Init(context.Background()))
	s.signer = keys.NewSigner(keys.WithKeys(k), keys.WithIssuer(testIssuer))

	reg, err := oidc.ParseClientRegistry("ui:" + testRedirectURI)
	s.Require().NoError(err)
	s.clients = reg

	s.store = newMemTokenStore()
	s.now = signNow
	s.seq = 0
	s.defaultLifetimes = false
	s.serve("example.com")
}

func (s *RefreshLifecycleSuite) TearDownTest() {
	s.srv.Close()
}

// serve (re)starts /token over the same store with the given allowlist, the
// way an operator restarts tempogate with a new OIDC_ALLOWED_DOMAINS.
func (s *RefreshLifecycleSuite) serve(allowedDomains string) {
	if s.srv != nil {
		s.srv.Close()
	}
	s.logs = &bytes.Buffer{}
	opts := []oidc.TokenOption{
		oidc.WithPermissionResolver(permitAll),
		oidc.WithTokenClock(s.clock),
		oidc.WithRefreshGenerator(s.nextRefresh),
		oidc.WithAllowedDomains(allowedDomains),
		oidc.WithTokenLogger(slog.New(slog.NewJSONHandler(s.logs, nil))),
		oidc.WithConnectors(googleConnectors(s.T(), nil, "")),
	}
	if !s.defaultLifetimes {
		opts = append(opts, oidc.WithTokenLifetimes(lcAccessTTL, lcRefreshTTL, lcMaxLife))
	}
	tok := oidc.NewToken(s.store, s.signer, s.clients, opts...)
	mux := http.NewServeMux()
	tok.Register(humago.New(mux, huma.DefaultConfig("test", "0.0.0")))
	s.srv = httptest.NewServer(mux)
	s.client = s.srv.Client()
}

func (s *RefreshLifecycleSuite) clock() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.now
}

func (s *RefreshLifecycleSuite) advance(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = s.now.Add(d)
}

func (s *RefreshLifecycleSuite) nextRefresh() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	return fmt.Sprintf("rt-%d", s.seq), nil
}

// login redeems an authorization code for email and returns the first
// refresh token of a new session.
func (s *RefreshLifecycleSuite) login(email string) string {
	code := fmt.Sprintf("code-%d", s.store.refreshCount())
	s.store.putCode(oidc.AuthCode{
		Code: code, ClientID: "ui", RedirectURI: testRedirectURI, ConnectorID: "google", Subject: "google-sub-" + email, Email: email,
		CodeChallenge: pkceChallenge, CodeChallengeMethod: "S256",
		CreatedAt: s.clock(), ExpiresAt: s.clock().Add(time.Minute),
	})
	f := url.Values{}
	f.Set("grant_type", "authorization_code")
	f.Set("code", code)
	f.Set("redirect_uri", testRedirectURI)
	f.Set("client_id", "ui")
	f.Set("code_verifier", pkceVerifier)
	status, rt, oerr := s.post(f)
	s.Require().Equalf(http.StatusOK, status, "login failed: %s", oerr)
	return rt
}

// refresh presents rt as client "ui" and returns the status, the rotated
// refresh token on success, and the OAuth error code otherwise.
func (s *RefreshLifecycleSuite) refresh(rt string) (int, string, string) {
	f := url.Values{}
	f.Set("grant_type", "refresh_token")
	f.Set("refresh_token", rt)
	f.Set("client_id", "ui")
	return s.post(f)
}

func (s *RefreshLifecycleSuite) post(f url.Values) (int, string, string) {
	resp, err := s.client.Post(s.srv.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader(f.Encode()))
	s.Require().NoError(err)
	defer resp.Body.Close()
	var body struct {
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		Error        string `json:"error"`
	}
	s.Require().NoError(json.NewDecoder(resp.Body).Decode(&body))
	return resp.StatusCode, body.RefreshToken, body.Error
}

func (s *RefreshLifecycleSuite) mustRefresh(rt string) string {
	status, next, oerr := s.refresh(rt)
	s.Require().Equalf(http.StatusOK, status, "refresh of %s failed: %s", rt, oerr)
	return next
}

func (s *RefreshLifecycleSuite) requireInvalidGrant(rt string) {
	status, _, oerr := s.refresh(rt)
	s.Equal(http.StatusBadRequest, status)
	s.Equal("invalid_grant", oerr)
}

// securityEvents returns the structured log records carrying an "event".
func (s *RefreshLifecycleSuite) securityEvents() []map[string]any {
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(s.logs.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		s.Require().NoError(json.Unmarshal([]byte(line), &rec))
		if _, ok := rec["event"]; ok {
			out = append(out, rec)
		}
	}
	return out
}

func (s *RefreshLifecycleSuite) TestLoginStartsNewFamilyAnchoredAtSignIn() {
	s.login("alice@example.com")
	s.login("alice@example.com")
	s.Require().Equal(2, s.store.refreshCount())

	first := s.store.savedRefresh[0]
	second := s.store.savedRefresh[1]
	s.NotEmpty(first.FamilyID)
	s.NotEqual(first.FamilyID, second.FamilyID, "every sign-in starts its own family")
	s.True(first.AuthTime.Equal(signNow), "auth_time is the sign-in time")
	s.True(first.ExpiresAt.Equal(signNow.Add(lcRefreshTTL)), "first token gets the idle lifetime")
}

func (s *RefreshLifecycleSuite) TestAccessTokenTTLIsConfigurable() {
	s.login("alice@example.com")
	rt := s.store.lastRefresh().Token
	f := url.Values{}
	f.Set("grant_type", "refresh_token")
	f.Set("refresh_token", rt)
	f.Set("client_id", "ui")
	resp, err := s.client.Post(s.srv.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader(f.Encode()))
	s.Require().NoError(err)
	defer resp.Body.Close()
	var body struct {
		ExpiresIn int `json:"expires_in"`
	}
	s.Require().NoError(json.NewDecoder(resp.Body).Decode(&body))
	s.Equal(int(lcAccessTTL.Seconds()), body.ExpiresIn)
}

// TestAbsoluteLifetimeCapsRotation is the H2 core: rotating inside the idle
// window keeps a session alive only until auth_time + max lifetime.
func (s *RefreshLifecycleSuite) TestAbsoluteLifetimeCapsRotation() {
	rt := s.login("alice@example.com")
	family := s.store.lastRefresh().FamilyID

	for range 3 {
		s.advance(20 * time.Hour)
		rt = s.mustRefresh(rt)
		saved := s.store.lastRefresh()
		s.Equal(family, saved.FamilyID, "rotation keeps the family")
		s.True(saved.AuthTime.Equal(signNow), "rotation carries auth_time")
		s.False(saved.ExpiresAt.After(signNow.Add(lcMaxLife)),
			"a rotated token never outlives auth_time + max lifetime (got %s)", saved.ExpiresAt)
	}
	// 60h in: the token minted now is capped at 72h, not 60h + 24h.
	s.True(s.store.lastRefresh().ExpiresAt.Equal(signNow.Add(lcMaxLife)))

	s.advance(12*time.Hour + time.Second)
	s.requireInvalidGrant(rt)
}

func (s *RefreshLifecycleSuite) TestIdleLifetimeExpiresUnusedSession() {
	rt := s.login("alice@example.com")
	s.advance(lcRefreshTTL + time.Second)
	s.requireInvalidGrant(rt)
}

// TestAbsoluteLifetimeEnforcedAtRefresh covers a token minted under a longer
// configuration (or backfilled by migration 0011): its stored expiry is still
// ahead, but the session is past auth_time + the current max lifetime.
func (s *RefreshLifecycleSuite) TestAbsoluteLifetimeEnforcedAtRefresh() {
	s.store.putRefresh(oidc.Refresh{
		Token: "legacy", JTI: "jti-legacy", ClientID: "ui", ConnectorID: "google", Subject: "google-sub-alice", Email: "alice@example.com",
		FamilyID: "legacy-family", AuthTime: signNow.Add(-lcMaxLife),
		CreatedAt: signNow.Add(-time.Hour), ExpiresAt: signNow.Add(29 * 24 * time.Hour),
	})
	s.requireInvalidGrant("legacy")
}

// TestUpgradeToSevenDayDefaultEndsOlderSessions: sessions minted while the
// default absolute lifetime was 30 days carry stored expiries up to 7 days
// ahead. After the upgrade, one signed in more than 7 days ago is refused at
// its next refresh; a younger one rotates, capped at sign-in + 7 days.
func (s *RefreshLifecycleSuite) TestUpgradeToSevenDayDefaultEndsOlderSessions() {
	s.Require().Equal(7*24*time.Hour, oidc.DefaultRefreshMaxLifetime)
	s.defaultLifetimes = true
	s.serve("example.com")

	day := 24 * time.Hour
	legacy := func(token string, signedIn time.Duration) {
		s.store.putRefresh(oidc.Refresh{
			Token: token, JTI: "jti-" + token, ClientID: "ui", ConnectorID: "google", Subject: "google-sub-alice", Email: "alice@example.com",
			FamilyID: "family-" + token, AuthTime: signNow.Add(-signedIn),
			// Last refreshed a day ago under the old defaults: 7-day idle
			// expiry, well inside sign-in + 30 days.
			CreatedAt: signNow.Add(-day), ExpiresAt: signNow.Add(6 * day),
		})
	}
	legacy("eight-days", 8*day)
	legacy("six-days", 6*day)

	s.requireInvalidGrant("eight-days")
	s.mustRefresh("six-days")
	s.True(s.store.lastRefresh().ExpiresAt.Equal(signNow.Add(day)),
		"the rotated token ends at sign-in + 7 days (got %s)", s.store.lastRefresh().ExpiresAt)
}

// TestRemovedDomainEndsSessionAndRevokesFamily: an operator removes a domain
// and restarts; the next refresh from that domain fails and the whole family
// is revoked, while other domains keep refreshing.
func (s *RefreshLifecycleSuite) TestRemovedDomainEndsSessionAndRevokesFamily() {
	rt := s.login("alice@example.com")
	family := s.store.lastRefresh().FamilyID
	bob := s.login("bob@corp.example.org")
	s.serve("example.com,corp.example.org")
	bob = s.mustRefresh(bob)

	s.serve("corp.example.org")
	s.requireInvalidGrant(rt)
	s.True(s.store.familyRevoked(family), "a refused domain revokes the family")
	s.mustRefresh(bob)

	events := s.securityEvents()
	s.Require().Len(events, 1)
	s.Equal("refresh_domain_not_allowed", events[0]["event"])
	s.Equal(family, events[0]["family_id"])
	s.Equal("alice@example.com", events[0]["email"])
}

// TestReplayRevokesNewerToken is the M3 acceptance: replaying a rotated
// token revokes its whole family, so the newer token the attacker (or the
// legitimate client) holds stops working too.
func (s *RefreshLifecycleSuite) TestReplayRevokesNewerToken() {
	rt1 := s.login("alice@example.com")
	family := s.store.lastRefresh().FamilyID
	other := s.login("alice@example.com")
	rt2 := s.mustRefresh(rt1)

	s.requireInvalidGrant(rt1)
	s.True(s.store.familyRevoked(family))
	s.requireInvalidGrant(rt2)
	s.mustRefresh(other)

	events := s.securityEvents()
	s.Require().Len(events, 1, "one security event for the replay; the revoked token is a plain miss")
	ev := events[0]
	s.Equal("refresh_token_reuse", ev["event"])
	s.Equal("WARN", ev["level"])
	s.Equal(family, ev["family_id"])
	s.Equal("ui", ev["client_id"])
	s.Equal("alice@example.com", ev["email"])
	s.NotContains(s.logs.String(), rt1, "token values never reach the log")
	s.NotContains(s.logs.String(), rt2, "token values never reach the log")
}

// TestReplayOfOtherClientsTombstoneIsPlainMiss: the client binding applies
// to tombstones too, so a client cannot revoke another client's family.
func (s *RefreshLifecycleSuite) TestReplayOfOtherClientsTombstoneIsPlainMiss() {
	rt1 := s.login("alice@example.com")
	family := s.store.lastRefresh().FamilyID
	s.mustRefresh(rt1)

	f := url.Values{}
	f.Set("grant_type", "refresh_token")
	f.Set("refresh_token", rt1)
	f.Set("client_id", "someone-else")
	status, _, _ := s.post(f)
	s.NotEqual(http.StatusOK, status)
	s.False(s.store.familyRevoked(family))
}

func (s *RefreshLifecycleSuite) TestRotationIntoRevokedFamilyIsInvalidGrant() {
	rt := s.login("alice@example.com")
	s.store.saveRefreshErr = fmt.Errorf("wrapped: %w", oidc.ErrRefreshFamilyRevoked)
	s.requireInvalidGrant(rt)
}

func (s *RefreshLifecycleSuite) TestRevokeFailureOnReplayIsServerError() {
	rt1 := s.login("alice@example.com")
	s.mustRefresh(rt1)
	s.store.revokeErr = errors.New("db exploded")
	status, _, _ := s.refresh(rt1)
	s.Equal(http.StatusInternalServerError, status)
}

func (s *RefreshLifecycleSuite) TestRevokeFailureOnDomainRefusalIsServerError() {
	rt := s.login("alice@example.com")
	s.serve("corp.example.org")
	s.store.revokeErr = errors.New("db exploded")
	status, _, _ := s.refresh(rt)
	s.Equal(http.StatusInternalServerError, status)
}

func TestValidateTokenLifetimes(t *testing.T) {
	cases := []struct {
		name              string
		access, idle, max time.Duration
		wantErr           string
	}{
		{name: "defaults", access: oidc.DefaultAccessTokenTTL, idle: oidc.DefaultRefreshTokenTTL, max: oidc.DefaultRefreshMaxLifetime},
		{name: "idle equals max", access: time.Hour, idle: 24 * time.Hour, max: 24 * time.Hour},
		{name: "zero access", idle: time.Hour, max: time.Hour, wantErr: "must all be positive"},
		{name: "negative idle", access: time.Minute, idle: -time.Hour, max: time.Hour, wantErr: "must all be positive"},
		{name: "zero max", access: time.Minute, idle: time.Hour, wantErr: "must all be positive"},
		{name: "access not shorter than idle", access: time.Hour, idle: time.Hour, max: 2 * time.Hour, wantErr: "OIDC_ACCESS_TOKEN_TTL"},
		{name: "idle beyond max", access: time.Minute, idle: 48 * time.Hour, max: 24 * time.Hour, wantErr: "OIDC_REFRESH_MAX_LIFETIME"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := oidc.ValidateTokenLifetimes(tc.access, tc.idle, tc.max)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

// TestRefreshWithoutAllowlistFailsClosed: a Token built without
// WithAllowedDomains honours no refresh, as the callback admits nobody.
func TestRefreshWithoutAllowlistFailsClosed(t *testing.T) {
	store := newMemTokenStore()
	store.putRefresh(oidc.Refresh{
		Token: "rt", ClientID: "ui", ConnectorID: "google", Subject: "google-sub-alice", Email: "alice@example.com", FamilyID: "f",
		AuthTime: signNow, CreatedAt: signNow, ExpiresAt: signNow.Add(time.Hour),
	})
	reg, err := oidc.ParseClientRegistry("ui:" + testRedirectURI)
	if err != nil {
		t.Fatal(err)
	}
	tok := oidc.NewToken(store, keys.NewSigner(), reg, oidc.WithPermissionResolver(permitAll), oidc.WithTokenClock(func() time.Time { return signNow }))
	mux := http.NewServeMux()
	tok.Register(humago.New(mux, huma.DefaultConfig("test", "0.0.0")))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/token", "application/x-www-form-urlencoded",
		strings.NewReader("grant_type=refresh_token&refresh_token=rt&client_id=ui"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", resp.StatusCode)
	}
}
