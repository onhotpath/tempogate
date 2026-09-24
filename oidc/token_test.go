package oidc_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
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

// memTokenStore satisfies oidc.TokenStore structurally. ConsumeAuthCode and
// ConsumeRefresh delete the row so single-use / rotation are exercised by the
// suite, not just asserted in prose.
type memTokenStore struct {
	mu                sync.Mutex
	codes             map[string]oidc.AuthCode
	refresh           map[string]oidc.Refresh
	savedRefresh      []oidc.Refresh
	consumeCodeErr    error
	consumeRefreshErr error
	saveRefreshErr    error
}

func newMemTokenStore() *memTokenStore {
	return &memTokenStore{
		codes:   map[string]oidc.AuthCode{},
		refresh: map[string]oidc.Refresh{},
	}
}

func (m *memTokenStore) putCode(ac oidc.AuthCode) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.codes[ac.Code] = ac
}

func (m *memTokenStore) putRefresh(r oidc.Refresh) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refresh[r.Token] = r
}

func (m *memTokenStore) ConsumeAuthCode(_ context.Context, code string) (oidc.AuthCode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.consumeCodeErr != nil {
		return oidc.AuthCode{}, m.consumeCodeErr
	}
	ac, ok := m.codes[code]
	if !ok {
		return oidc.AuthCode{}, oidc.ErrAuthCodeNotFound
	}
	delete(m.codes, code)
	return ac, nil
}

func (m *memTokenStore) SaveRefresh(_ context.Context, r oidc.Refresh) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.saveRefreshErr != nil {
		return m.saveRefreshErr
	}
	m.savedRefresh = append(m.savedRefresh, r)
	m.refresh[r.Token] = r
	return nil
}

func (m *memTokenStore) ConsumeRefresh(_ context.Context, token string) (oidc.Refresh, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.consumeRefreshErr != nil {
		return oidc.Refresh{}, m.consumeRefreshErr
	}
	r, ok := m.refresh[token]
	if !ok {
		return oidc.Refresh{}, oidc.ErrRefreshNotFound
	}
	delete(m.refresh, token)
	return r, nil
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
		keys.WithTokenClock(func() time.Time { return signNow }),
	)
	s.verifier = keys.NewVerifier(
		keys.WithKeys(s.keys),
		keys.WithIssuer(testIssuer),
		keys.WithTokenClock(func() time.Time { return signNow.Add(time.Minute) }),
	)

	reg, err := oidc.ParseClientRegistry("ui:" + testRedirectURI + ",webui:" + testRedirectURI + ",tempogate-device:" + testRedirectURI)
	s.Require().NoError(err)
	s.Require().NoError(reg.WithSecrets("webui:" + confidentialSecret))
	s.clients = reg

	s.store = newMemTokenStore()
	s.deviceStore = newMemDeviceFlowStore()
	tok := oidc.NewToken(s.store, signer, s.clients,
		oidc.WithTokenClock(func() time.Time { return signNow }),
		oidc.WithRefreshGenerator(func() (string, error) { return fixedRefresh, nil }),
		oidc.WithDeviceCodeStore(s.deviceStore),
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
	aud, ok := tok.Audience()
	s.Require().True(ok)
	s.Equal([]string{"webui"}, aud, "OIDC ID token aud must be the requesting client_id")
	nonce, err := jwxjwt.Get[string](tok, "nonce")
	s.Require().NoError(err)
	s.Equal("rp-nonce-xyz", nonce, "nonce from /authorize must round-trip into the token")
	sub, _ := tok.Subject()
	s.Equal("alice@example.com", sub)
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
	tok, err := s.verifier.Verify(context.Background(), body.AccessToken)
	s.Require().NoError(err)
	aud, _ := tok.Audience()
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

func (s *TokenSuite) TestConfidentialMissingAnyProofIsInvalidRequest() {
	s.store.putCode(s.confAuthCode("conf-1"))

	resp := s.post(confCodeForm()) // no code_verifier, no client_secret
	defer resp.Body.Close()

	s.Equal(http.StatusBadRequest, resp.StatusCode)
	s.Equal("invalid_request", s.decodeOAuthError(resp))
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

	tok, err := s.verifier.Verify(context.Background(), s.decodeTokenResponse(resp).AccessToken)
	s.Require().NoError(err)
	aud, _ := tok.Audience()
	s.Equal([]string{"ui"}, aud)
	nonce, err := jwxjwt.Get[string](tok, "nonce")
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
	s.Equal(body.AccessToken, body.IDToken, "id_token must be the same signed JWT")
	s.NotEmpty(body.AccessToken)

	tok, err := s.verifier.Verify(context.Background(), body.AccessToken)
	s.Require().NoError(err, "JWT must verify against our JWKS")

	sub, ok := tok.Subject()
	s.Require().True(ok)
	s.Equal("alice@example.com", sub)

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
	s.Equal("ui", saved.ClientID)
	s.NotEmpty(saved.JTI)
	gotJTI, ok := tok.JwtID()
	s.Require().True(ok)
	s.Equal(gotJTI, saved.JTI, "refresh row must reference the access token jti")
	s.Equal(30*24*time.Hour, saved.ExpiresAt.Sub(saved.CreatedAt))
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
	f.Set("code_verifier", "the-wrong-verifier")
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

	f := authCodeForm()
	f.Set("client_id", "someone-else")
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
		Token:     "old-refresh",
		JTI:       "old-jti",
		ClientID:  "ui",
		Email:     "alice@example.com",
		CreatedAt: signNow,
		ExpiresAt: signNow.Add(30 * 24 * time.Hour),
	})

	f := url.Values{}
	f.Set("grant_type", "refresh_token")
	f.Set("refresh_token", "old-refresh")
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
	s.Equal("alice@example.com", sub)

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
			Token: "stale", Email: "alice@example.com", ClientID: "ui",
			CreatedAt: signNow.Add(-48 * time.Hour), ExpiresAt: signNow.Add(-time.Second),
		}, "invalid_grant"},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			if tc.seed != nil {
				s.store.putRefresh(*tc.seed)
			}
			f := url.Values{}
			f.Set("grant_type", "refresh_token")
			if tc.token != "" {
				f.Set("refresh_token", tc.token)
			} else {
				f.Set("filler", "x")
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
	tok := oidc.NewToken(store, keys.NewSigner(), s.clients, // no keypair ⇒ Mint fails
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
	tok := oidc.NewToken(store, signer, s.clients,
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
