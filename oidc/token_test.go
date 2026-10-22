package oidc_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	jwxjwt "github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/suite"

	"github.com/onhotpath/tempogate/keys"
	"github.com/onhotpath/tempogate/oidc"
)

// toStringSlice converts the permissions claim (decoded as []any) to []string
// for assertion. Mirrors keys/signer_test.go's helper of the same shape.
func toStringSlice(t *testing.T, v any) []string {
	t.Helper()
	raw, ok := v.([]any)
	if !ok {
		t.Fatalf("permissions claim should decode to []any, got %T", v)
	}
	out := make([]string, len(raw))
	for i, e := range raw {
		s, ok := e.(string)
		if !ok {
			t.Fatalf("permission entry %d not a string: %T", i, e)
		}
		out[i] = s
	}
	return out
}

// RFC 7636 Appendix B canonical PKCE pair: SHA-256(verifier) base64url-encoded
// equals the challenge. Reused so the test asserts the real S256 binding, not
// a hand-rolled hash.
const (
	pkceVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	pkceChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	fixedRefresh = "fixed-refresh-token"
)

var signNow = time.Unix(1700000000, 0).UTC()

// memKeyStore is the in-memory keys.KeyStore the test signer is built over.
// oidc_test cannot reach package keys' internal fakeKeyStore, so it owns one.
type memKeyStore struct {
	mu  sync.Mutex
	kps []keys.Keypair
}

func (m *memKeyStore) SaveKeypair(_ context.Context, kp keys.Keypair) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.kps = append(m.kps, kp)
	return nil
}

func (m *memKeyStore) LoadKeypairs(_ context.Context) ([]keys.Keypair, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]keys.Keypair, len(m.kps))
	copy(out, m.kps)
	return out, nil
}

func (m *memKeyStore) RetireKeypair(context.Context, string, time.Time) (keys.Keypair, error) {
	return keys.Keypair{}, keys.ErrKeypairNotFound
}

// memTokenStore satisfies oidc.TokenStore structurally. ConsumeAuthCode and
// ConsumeRefresh both tombstone, so single use, rotation and reuse detection
// are exercised by the suite, not just asserted in prose; ConsumeRefresh
// honours the client binding and family revocation the same way the sqlite
// store's conditional UPDATE does.
type memTokenStore struct {
	mu                sync.Mutex
	codes             map[string]oidc.AuthCode
	consumedCodes     map[string]bool
	refresh           map[string]oidc.Refresh
	consumed          map[string]bool
	revokedFamilies   map[string]bool
	savedRefresh      []oidc.Refresh
	consumeCodeErr    error
	consumeRefreshErr error
	saveRefreshErr    error
	revokeErr         error
}

func newMemTokenStore() *memTokenStore {
	return &memTokenStore{
		codes:           map[string]oidc.AuthCode{},
		consumedCodes:   map[string]bool{},
		refresh:         map[string]oidc.Refresh{},
		consumed:        map[string]bool{},
		revokedFamilies: map[string]bool{},
	}
}

// putCode seeds a live code, replacing any earlier row or tombstone under
// the same value.
func (m *memTokenStore) putCode(ac oidc.AuthCode) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.codes[ac.Code] = ac
	delete(m.consumedCodes, ac.Code)
}

// putRefresh seeds a live token, replacing any earlier row or tombstone
// under the same value.
func (m *memTokenStore) putRefresh(r oidc.Refresh) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refresh[r.Token] = r
	delete(m.consumed, r.Token)
}

func (m *memTokenStore) ConsumeAuthCode(_ context.Context, code, familyID string, _ time.Time) (oidc.AuthCode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.consumeCodeErr != nil {
		return oidc.AuthCode{}, m.consumeCodeErr
	}
	ac, ok := m.codes[code]
	if !ok {
		return oidc.AuthCode{}, oidc.ErrAuthCodeNotFound
	}
	if m.consumedCodes[code] {
		return ac, oidc.ErrAuthCodeReused
	}
	ac.FamilyID = familyID
	m.codes[code] = ac
	m.consumedCodes[code] = true
	return ac, nil
}

func (m *memTokenStore) SaveRefresh(_ context.Context, r oidc.Refresh) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.saveRefreshErr != nil {
		return m.saveRefreshErr
	}
	if m.revokedFamilies[r.FamilyID] {
		return oidc.ErrRefreshFamilyRevoked
	}
	m.savedRefresh = append(m.savedRefresh, r)
	m.refresh[r.Token] = r
	return nil
}

func (m *memTokenStore) ConsumeRefresh(_ context.Context, token, clientID string, _ time.Time) (oidc.Refresh, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.consumeRefreshErr != nil {
		return oidc.Refresh{}, m.consumeRefreshErr
	}
	r, ok := m.refresh[token]
	if !ok || r.ClientID != clientID {
		return oidc.Refresh{}, oidc.ErrRefreshNotFound
	}
	if m.consumed[token] {
		return r, oidc.ErrRefreshReused
	}
	if m.revokedFamilies[r.FamilyID] {
		return oidc.Refresh{}, oidc.ErrRefreshNotFound
	}
	m.consumed[token] = true
	return r, nil
}

func (m *memTokenStore) RevokeRefreshFamily(_ context.Context, familyID string, _ time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.revokeErr != nil {
		return 0, m.revokeErr
	}
	n := 0
	for tok, r := range m.refresh {
		if r.FamilyID == familyID && !m.consumed[tok] && !m.revokedFamilies[familyID] {
			n++
		}
	}
	m.revokedFamilies[familyID] = true
	return n, nil
}

// hasRefresh reports whether token is live: saved, not consumed, and not in a
// revoked family.
func (m *memTokenStore) hasRefresh(token string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.refresh[token]
	return ok && !m.consumed[token] && !m.revokedFamilies[r.FamilyID]
}

func (m *memTokenStore) familyRevoked(familyID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.revokedFamilies[familyID]
}

func (m *memTokenStore) lastRefresh() oidc.Refresh {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.savedRefresh[len(m.savedRefresh)-1]
}

func (m *memTokenStore) refreshCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.savedRefresh)
}

type TokenSuite struct {
	suite.Suite

	store       *memTokenStore
	deviceStore *memDeviceFlowStore
	keys        *keys.Keys
	verifier    *keys.Verifier
	clients     oidc.ClientRegistry
	srv         *httptest.Server
	client      *http.Client
	observed    *recordingObserver
	resolver    *stubResolver
	logs        *bytes.Buffer
}

// confidentialSecret is the shared secret for the test's older-style
// confidential client; the PKCE carve-out admits a no-challenge code only
// when this is presented at /token.
const confidentialSecret = "ui-confidential-secret"

func TestTokenSuite(t *testing.T) {
	suite.Run(t, new(TokenSuite))
}

func (s *TokenSuite) SetupTest() {
	ks := &memKeyStore{}
	s.keys = keys.New(keys.WithStore(ks), keys.WithGenerateOptions(keys.WithRSABits(2048)))
	s.Require().NoError(s.keys.Init(context.Background()))

	signer := keys.NewSigner(
		keys.WithKeys(s.keys),
		keys.WithIssuer(testIssuer),
		keys.WithAudience(testAccessAudience),
		keys.WithTokenClock(func() time.Time { return signNow }),
	)
	s.verifier = keys.NewVerifier(
		keys.WithKeys(s.keys),
		keys.WithIssuer(testIssuer),
		keys.WithAudience(testAccessAudience),
		keys.WithTokenClock(func() time.Time { return signNow.Add(time.Minute) }),
	)

	reg, err := oidc.ParseClientRegistry("ui:" + testRedirectURI + ",webui:" + testRedirectURI + ",tempogate-device:")
	s.Require().NoError(err)
	s.Require().NoError(reg.WithSecrets("webui:" + confidentialSecret))
	s.clients = reg

	s.store = newMemTokenStore()
	s.deviceStore = newMemDeviceFlowStore()
	s.observed = &recordingObserver{}
	s.resolver = newStubResolver("temporal-system:admin")
	s.logs = &bytes.Buffer{}
	tok := oidc.NewToken(s.store, signer, s.clients, oidc.WithPermissionResolver(s.resolver),
		oidc.WithTokenObserver(s.observed),
		oidc.WithAuthzObserver(s.observed),
		oidc.WithTokenLogger(slog.New(slog.NewTextHandler(s.logs, nil))),
		oidc.WithTokenClock(func() time.Time { return signNow }),
		oidc.WithRefreshGenerator(func() (string, error) { return fixedRefresh, nil }),
		oidc.WithDeviceCodeStore(s.deviceStore),
		oidc.WithAllowedDomains("example.com"),
		oidc.WithConnectors(googleConnectors(s.T(), nil, "")),
	)
	mux := http.NewServeMux()
	tok.Register(humago.New(mux, huma.DefaultConfig("test", "0.0.0")))
	s.srv = httptest.NewServer(mux)
	s.client = &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (s *TokenSuite) TearDownTest() {
	s.srv.Close()
}

func (s *TokenSuite) authCode(code string) oidc.AuthCode {
	return oidc.AuthCode{
		Code:                code,
		ClientID:            "ui",
		RedirectURI:         testRedirectURI,
		ConnectorID:         "google",
		Subject:             "google-sub-alice",
		Email:               "alice@example.com",
		Scope:               "openid email",
		CodeChallenge:       pkceChallenge,
		CodeChallengeMethod: "S256",
		CreatedAt:           signNow,
		ExpiresAt:           signNow.Add(time.Minute),
	}
}

func (s *TokenSuite) post(form url.Values) *http.Response {
	resp, err := s.client.Post(s.srv.URL+"/token",
		"application/x-www-form-urlencoded",
		strings.NewReader(form.Encode()))
	s.Require().NoError(err)
	return resp
}

func authCodeForm() url.Values {
	f := url.Values{}
	f.Set("grant_type", "authorization_code")
	f.Set("code", "code-1")
	f.Set("redirect_uri", testRedirectURI)
	f.Set("client_id", "ui")
	f.Set("code_verifier", pkceVerifier)
	return f
}

// confAuthCode is a code minted for the confidential client (no PKCE
// challenge, a nonce carried from /authorize) — the shape /callback produces
// for an older-style client like the Temporal Web UI.
func (s *TokenSuite) confAuthCode(code string) oidc.AuthCode {
	return oidc.AuthCode{
		Code:        code,
		ClientID:    "webui",
		RedirectURI: testRedirectURI,
		ConnectorID: "google",
		Subject:     "google-sub-alice",
		Email:       "alice@example.com",
		Scope:       "openid email",
		Nonce:       "rp-nonce-xyz",
		CreatedAt:   signNow,
		ExpiresAt:   signNow.Add(time.Minute),
	}
}

func confCodeForm() url.Values {
	f := url.Values{}
	f.Set("grant_type", "authorization_code")
	f.Set("code", "conf-1")
	f.Set("redirect_uri", testRedirectURI)
	f.Set("client_id", "webui")
	return f
}

// postBasic mirrors golang.org/x/oauth2 under AuthStyleInHeader: client
// credentials are form-url-encoded then HTTP-Basic'd, never sent in the body.
func (s *TokenSuite) postBasic(form url.Values, id, secret string) *http.Response {
	req, err := http.NewRequest(http.MethodPost, s.srv.URL+"/token", strings.NewReader(form.Encode()))
	s.Require().NoError(err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(id), url.QueryEscape(secret))
	resp, err := s.client.Do(req)
	s.Require().NoError(err)
	return resp
}

func (s *TokenSuite) TestConfidentialClientSecretViaFormBodyMintsJWT() {
	s.store.putCode(s.confAuthCode("conf-1"))

	f := confCodeForm()
	f.Set("client_secret", confidentialSecret)
	resp := s.post(f)
	defer resp.Body.Close()

	s.Require().Equal(http.StatusOK, resp.StatusCode)
	body := s.decodeTokenResponse(resp)

	tok, err := s.verifier.Verify(context.Background(), body.AccessToken)
	s.Require().NoError(err)
	clientID, err := jwxjwt.Get[string](tok, "client_id")
	s.Require().NoError(err)
	s.Equal("webui", clientID)
	sub, _ := tok.Subject()
	s.Equal("google:google-sub-alice", sub)

	id := s.parseIDToken(body.IDToken)
	aud, _ := id.Audience()
	s.Equal([]string{"webui"}, aud, "OIDC ID token aud must be the requesting client_id")
	nonce, err := jwxjwt.Get[string](id, "nonce")
	s.Require().NoError(err)
	s.Equal("rp-nonce-xyz", nonce, "nonce from /authorize must round-trip into the ID token")
	idSub, _ := id.Subject()
	s.Equal("google:google-sub-alice", idSub, "the ID token carries the same sub")
}

func (s *TokenSuite) TestConfidentialClientSecretViaHTTPBasicMintsJWT() {
	s.store.putCode(s.confAuthCode("conf-1"))

	// No client_id/client_secret in the body: both come from the Basic header.
	f := url.Values{}
	f.Set("grant_type", "authorization_code")
	f.Set("code", "conf-1")
	f.Set("redirect_uri", testRedirectURI)

	resp := s.postBasic(f, "webui", confidentialSecret)
	defer resp.Body.Close()

	s.Require().Equal(http.StatusOK, resp.StatusCode)
	body := s.decodeTokenResponse(resp)
	_, err := s.verifier.Verify(context.Background(), body.AccessToken)
	s.Require().NoError(err)
	aud, _ := s.parseIDToken(body.IDToken).Audience()
	s.Equal([]string{"webui"}, aud)
}

func (s *TokenSuite) TestConfidentialWrongSecretIsInvalidClient() {
	s.store.putCode(s.confAuthCode("conf-1"))

	f := confCodeForm()
	f.Set("client_secret", "not-the-secret")
	resp := s.post(f)
	defer resp.Body.Close()

	s.Equal(http.StatusUnauthorized, resp.StatusCode)
	s.Equal("invalid_client", s.decodeOAuthError(resp))
}

func (s *TokenSuite) TestConfidentialMissingAnyProofIsInvalidClient() {
	s.store.putCode(s.confAuthCode("conf-1"))

	resp := s.post(confCodeForm()) // no code_verifier, no client_secret
	defer resp.Body.Close()

	s.Equal(http.StatusUnauthorized, resp.StatusCode)
	s.Equal("invalid_client", s.decodeOAuthError(resp))
}

// TestPublicClientCannotRideTheCarveOut proves the relaxation is strictly
// secret-gated: a code with no PKCE challenge bound to a *public* client
// (no registered secret) cannot be redeemed even when a secret is presented —
// Authenticate fails closed, so this never degrades to "no PKCE, no auth".
func (s *TokenSuite) TestPublicClientCannotRideTheCarveOut() {
	ac := s.authCode("pub-nopkce")
	ac.CodeChallenge = "" // a public client could never have produced this at /authorize; defense in depth at /token
	s.store.putCode(ac)

	f := url.Values{}
	f.Set("grant_type", "authorization_code")
	f.Set("code", "pub-nopkce")
	f.Set("redirect_uri", testRedirectURI)
	f.Set("client_id", "ui")
	f.Set("client_secret", "anything")
	resp := s.post(f)
	defer resp.Body.Close()

	s.Equal(http.StatusUnauthorized, resp.StatusCode)
	s.Equal("invalid_client", s.decodeOAuthError(resp))
}

func (s *TokenSuite) TestPKCEPathStampsAudAndNonce() {
	ac := s.authCode("code-1")
	ac.Nonce = "rp-nonce-pkce"
	s.store.putCode(ac)

	resp := s.post(authCodeForm())
	defer resp.Body.Close()
	s.Require().Equal(http.StatusOK, resp.StatusCode)

	id := s.parseIDToken(s.decodeTokenResponse(resp).IDToken)
	aud, _ := id.Audience()
	s.Equal([]string{"ui"}, aud)
	nonce, err := jwxjwt.Get[string](id, "nonce")
	s.Require().NoError(err)
	s.Equal("rp-nonce-pkce", nonce)
}

func (s *TokenSuite) decodeTokenResponse(resp *http.Response) struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
} {
	var body struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
	}
	s.Require().NoError(json.NewDecoder(resp.Body).Decode(&body))
	return body
}

func (s *TokenSuite) decodeOAuthError(resp *http.Response) string {
	var body struct {
		Error string `json:"error"`
		Desc  string `json:"error_description"`
	}
	s.Require().NoError(json.NewDecoder(resp.Body).Decode(&body))
	s.NotEmpty(body.Desc)
	return body.Error
}

func (s *TokenSuite) TestAuthorizationCodeGrantMintsVerifiableJWT() {
	s.store.putCode(s.authCode("code-1"))

	resp := s.post(authCodeForm())
	defer resp.Body.Close()

	s.Require().Equal(http.StatusOK, resp.StatusCode)
	s.Equal("no-store", resp.Header.Get("Cache-Control"))
	s.Equal("no-cache", resp.Header.Get("Pragma"))

	body := s.decodeTokenResponse(resp)
	s.Equal("Bearer", body.TokenType)
	s.Equal(14400, body.ExpiresIn)
	s.Equal(fixedRefresh, body.RefreshToken)
	s.NotEmpty(body.AccessToken)
	s.NotEqual(body.AccessToken, body.IDToken, "the ID token is a separate token")

	tok, err := s.verifier.Verify(context.Background(), body.AccessToken)
	s.Require().NoError(err, "JWT must verify against our JWKS")

	sub, ok := tok.Subject()
	s.Require().True(ok)
	s.Equal("google:google-sub-alice", sub, "sub is the connector and Google's stable, never-reused account id, not the email")

	email, err := jwxjwt.Get[string](tok, "email")
	s.Require().NoError(err)
	s.Equal("alice@example.com", email)

	perms, ok := tok.Field("permissions")
	s.Require().True(ok)
	s.Equal([]string{"temporal-system:admin"}, toStringSlice(s.T(), perms))

	exp, ok := tok.Expiration()
	s.Require().True(ok)
	s.True(exp.Equal(signNow.Add(4*time.Hour)), "exp must be 4h out: got %v", exp)

	s.Require().Equal(1, s.store.refreshCount())
	saved := s.store.lastRefresh()
	s.Equal(fixedRefresh, saved.Token)
	s.Equal("alice@example.com", saved.Email)
	s.Equal("google-sub-alice", saved.Subject, "the refresh row must carry the subject so a refresh keeps it")
	s.Equal("ui", saved.ClientID)
	s.NotEmpty(saved.JTI)
	gotJTI, ok := tok.JwtID()
	s.Require().True(ok)
	s.Equal(gotJTI, saved.JTI, "refresh row must reference the access token jti")
	s.Equal(oidc.DefaultRefreshTokenTTL, saved.ExpiresAt.Sub(saved.CreatedAt), "a new session gets the idle lifetime")
	s.True(saved.AuthTime.Equal(signNow), "auth_time is the sign-in time")
	s.NotEmpty(saved.FamilyID)
}

func (s *TokenSuite) TestCodeWithoutSubjectIsInvalidGrant() {
	ac := s.authCode("code-1")
	ac.Subject = ""
	s.store.putCode(ac)

	resp := s.post(authCodeForm())
	defer resp.Body.Close()

	s.Equal(http.StatusBadRequest, resp.StatusCode)
	s.Equal("invalid_grant", s.decodeOAuthError(resp))
	s.Zero(s.store.refreshCount())
}

func (s *TokenSuite) TestReusedCodeIsInvalidGrant() {
	s.store.putCode(s.authCode("code-1"))

	first := s.post(authCodeForm())
	first.Body.Close()
	s.Require().Equal(http.StatusOK, first.StatusCode)

	second := s.post(authCodeForm())
	defer second.Body.Close()
	s.Equal(http.StatusBadRequest, second.StatusCode)
	s.Equal("invalid_grant", s.decodeOAuthError(second))
}

func (s *TokenSuite) TestUnknownCodeIsInvalidGrant() {
	resp := s.post(authCodeForm())
	defer resp.Body.Close()
	s.Equal(http.StatusBadRequest, resp.StatusCode)
	s.Equal("invalid_grant", s.decodeOAuthError(resp))
}

func (s *TokenSuite) TestPKCEMismatchIsInvalidGrant() {
	s.store.putCode(s.authCode("code-1"))

	f := authCodeForm()
	f.Set("code_verifier", strings.Repeat("w", 43)) // well-formed, but not this code's
	resp := s.post(f)
	defer resp.Body.Close()

	s.Equal(http.StatusBadRequest, resp.StatusCode)
	s.Equal("invalid_grant", s.decodeOAuthError(resp))
}

func (s *TokenSuite) TestExpiredCodeIsInvalidGrant() {
	ac := s.authCode("code-1")
	ac.ExpiresAt = signNow.Add(-time.Second)
	s.store.putCode(ac)

	resp := s.post(authCodeForm())
	defer resp.Body.Close()
	s.Equal(http.StatusBadRequest, resp.StatusCode)
	s.Equal("invalid_grant", s.decodeOAuthError(resp))
}

func (s *TokenSuite) TestClientIDMismatchIsInvalidGrant() {
	s.store.putCode(s.authCode("code-1"))

	// A different, fully authenticated client cannot redeem ui's code.
	f := authCodeForm()
	f.Set("client_id", "webui")
	f.Set("client_secret", confidentialSecret)
	resp := s.post(f)
	defer resp.Body.Close()
	s.Equal(http.StatusBadRequest, resp.StatusCode)
	s.Equal("invalid_grant", s.decodeOAuthError(resp))
}

func (s *TokenSuite) TestRedirectURIMismatchIsInvalidGrant() {
	s.store.putCode(s.authCode("code-1"))

	f := authCodeForm()
	f.Set("redirect_uri", "https://app.example.com/elsewhere")
	resp := s.post(f)
	defer resp.Body.Close()
	s.Equal(http.StatusBadRequest, resp.StatusCode)
	s.Equal("invalid_grant", s.decodeOAuthError(resp))
}

func (s *TokenSuite) TestMissingCodeOrVerifierIsInvalidRequest() {
	cases := []struct {
		name string
		drop string
	}{
		{"missing code", "code"},
		{"missing code_verifier", "code_verifier"},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			f := authCodeForm()
			f.Del(tc.drop)
			resp := s.post(f)
			defer resp.Body.Close()
			s.Equal(http.StatusBadRequest, resp.StatusCode)
			s.Equal("invalid_request", s.decodeOAuthError(resp))
		})
	}
}

func (s *TokenSuite) TestGrantTypeDispatch() {
	cases := []struct {
		name      string
		grantType string
		wantErr   string
	}{
		{"missing grant_type", "", "invalid_request"},
		{"unsupported grant_type", "client_credentials", "unsupported_grant_type"},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			f := url.Values{}
			if tc.grantType != "" {
				f.Set("grant_type", tc.grantType)
			}
			f.Set("filler", "x") // keep the body non-empty
			resp := s.post(f)
			defer resp.Body.Close()
			s.Equal(http.StatusBadRequest, resp.StatusCode)
			s.Equal(tc.wantErr, s.decodeOAuthError(resp))
		})
	}
}

func (s *TokenSuite) TestRefreshTokenGrantRotatesAndMintsSamePermissions() {
	s.store.putRefresh(oidc.Refresh{
		Token:       "old-refresh",
		JTI:         "old-jti",
		ClientID:    "ui",
		ConnectorID: "google",
		Subject:     "google-sub-alice",
		Email:       "alice@example.com",
		FamilyID:    "old-family",
		AuthTime:    signNow,
		CreatedAt:   signNow,
		ExpiresAt:   signNow.Add(7 * 24 * time.Hour),
	})

	f := url.Values{}
	f.Set("grant_type", "refresh_token")
	f.Set("refresh_token", "old-refresh")
	f.Set("client_id", "ui")
	resp := s.post(f)
	defer resp.Body.Close()

	s.Require().Equal(http.StatusOK, resp.StatusCode)
	body := s.decodeTokenResponse(resp)
	s.Equal(fixedRefresh, body.RefreshToken)
	s.NotEqual("old-refresh", body.RefreshToken, "refresh token must rotate")

	tok, err := s.verifier.Verify(context.Background(), body.AccessToken)
	s.Require().NoError(err)
	perms, ok := tok.Field("permissions")
	s.Require().True(ok)
	s.Equal([]string{"temporal-system:admin"}, toStringSlice(s.T(), perms))
	sub, _ := tok.Subject()
	s.Equal("google:google-sub-alice", sub, "a refreshed token keeps the original subject")
	email, err := jwxjwt.Get[string](tok, "email")
	s.Require().NoError(err)
	s.Equal("alice@example.com", email)
	s.Equal("google-sub-alice", s.store.lastRefresh().Subject, "the rotated refresh row keeps the subject")

	// Old token was consumed; presenting it again fails.
	again := s.post(f)
	defer again.Body.Close()
	s.Equal(http.StatusBadRequest, again.StatusCode)
	s.Equal("invalid_grant", s.decodeOAuthError(again))
}

func (s *TokenSuite) TestRefreshTokenGrantErrors() {
	cases := []struct {
		name    string
		token   string
		seed    *oidc.Refresh
		wantErr string
	}{
		{"missing refresh_token", "", nil, "invalid_request"},
		{"unknown refresh_token", "nope", nil, "invalid_grant"},
		{"expired refresh_token", "stale", &oidc.Refresh{
			Token: "stale", ConnectorID: "google", Subject: "google-sub-alice", Email: "alice@example.com", ClientID: "ui",
			CreatedAt: signNow.Add(-48 * time.Hour), ExpiresAt: signNow.Add(-time.Second),
		}, "invalid_grant"},
		// Minted before migration 0010 (no subject, and without the hd
		// check): rejected so the holder re-authenticates once.
		{"pre-upgrade refresh_token without subject", "legacy", &oidc.Refresh{
			Token: "legacy", Email: "alice@example.com", ClientID: "ui",
			CreatedAt: signNow, ExpiresAt: signNow.Add(time.Hour),
		}, "invalid_grant"},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			if tc.seed != nil {
				s.store.putRefresh(*tc.seed)
			}
			f := url.Values{}
			f.Set("grant_type", "refresh_token")
			f.Set("client_id", "ui")
			if tc.token != "" {
				f.Set("refresh_token", tc.token)
			}
			resp := s.post(f)
			defer resp.Body.Close()
			s.Equal(http.StatusBadRequest, resp.StatusCode)
			s.Equal(tc.wantErr, s.decodeOAuthError(resp))
		})
	}
}

func (s *TokenSuite) TestMalformedBodyIsInvalidRequest() {
	resp, err := s.client.Post(s.srv.URL+"/token",
		"application/x-www-form-urlencoded",
		strings.NewReader("%zz=%"))
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusBadRequest, resp.StatusCode)
	s.Equal("invalid_request", s.decodeOAuthError(resp))
}

func (s *TokenSuite) TestSaveRefreshFailureIsServerError() {
	s.store.putCode(s.authCode("code-1"))
	s.store.saveRefreshErr = errors.New("disk full")

	resp := s.post(authCodeForm())
	defer resp.Body.Close()
	s.Equal(http.StatusInternalServerError, resp.StatusCode)
}

func (s *TokenSuite) TestConsumeCodeErrorOtherThanNotFoundIsServerError() {
	s.store.consumeCodeErr = errors.New("db exploded")

	resp := s.post(authCodeForm())
	defer resp.Body.Close()
	s.Equal(http.StatusInternalServerError, resp.StatusCode)
}

func (s *TokenSuite) TestSignerWithoutKeysIsServerError() {
	store := newMemTokenStore()
	store.putCode(s.authCode("code-1"))
	tok := oidc.NewToken(store, keys.NewSigner(), s.clients, oidc.WithPermissionResolver(permitAll), // no keypair ⇒ Mint fails
		oidc.WithTokenClock(func() time.Time { return signNow }),
	)
	mux := http.NewServeMux()
	tok.Register(humago.New(mux, huma.DefaultConfig("test", "0.0.0")))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := s.client.Post(srv.URL+"/token",
		"application/x-www-form-urlencoded",
		strings.NewReader(authCodeForm().Encode()))
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusInternalServerError, resp.StatusCode)
}

func (s *TokenSuite) TestDefaultRefreshGeneratorIsOpaque() {
	store := newMemTokenStore()
	store.putCode(s.authCode("code-1"))
	signer := keys.NewSigner(keys.WithKeys(s.keys), keys.WithIssuer(testIssuer))
	tok := oidc.NewToken(store, signer, s.clients, oidc.WithPermissionResolver(permitAll),
		oidc.WithTokenClock(func() time.Time { return signNow }),
	) // no WithRefreshGenerator: exercises crypto/rand path
	mux := http.NewServeMux()
	tok.Register(humago.New(mux, huma.DefaultConfig("test", "0.0.0")))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := s.client.Post(srv.URL+"/token",
		"application/x-www-form-urlencoded",
		strings.NewReader(authCodeForm().Encode()))
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusOK, resp.StatusCode)

	body := s.decodeTokenResponse(resp)
	raw, err := base64.RawURLEncoding.DecodeString(body.RefreshToken)
	s.Require().NoError(err)
	s.Len(raw, 32)
}

// TestOversizedParamsRejected bounds the credentials /token hashes and looks
// up; the limits are generous upper bounds, not format checks.
func (s *TokenSuite) TestOversizedParamsRejected() {
	long := strings.Repeat("a", 1025)
	cases := []struct {
		name  string
		param string
		form  url.Values
	}{
		{"code", "code", authCodeForm()},
		{"code_verifier", "code_verifier", authCodeForm()},
		{"redirect_uri", "redirect_uri", authCodeForm()},
		{"client_id", "client_id", authCodeForm()},
		{"refresh_token", "refresh_token", url.Values{"grant_type": {"refresh_token"}, "client_id": {"ui"}}},
		{"device_code", "device_code", url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "client_id": {"tempogate-device"}}},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			s.store.putCode(s.authCode("code-1"))
			tc.form.Set(tc.param, long+strings.Repeat("a", 2048))
			resp := s.post(tc.form)
			defer resp.Body.Close()

			s.Equal(http.StatusBadRequest, resp.StatusCode)
			var body struct {
				Error string `json:"error"`
				Desc  string `json:"error_description"`
			}
			s.Require().NoError(json.NewDecoder(resp.Body).Decode(&body))
			s.Equal("invalid_request", body.Error)
			s.Contains(body.Desc, tc.param)
		})
	}
	s.Empty(s.store.savedRefresh, "no token was issued")
}
