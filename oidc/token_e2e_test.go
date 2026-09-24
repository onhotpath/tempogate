package oidc_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/suite"

	"github.com/onhotpath/tempogate/api"
	"github.com/onhotpath/tempogate/keys"
	"github.com/onhotpath/tempogate/oidc"
	"github.com/onhotpath/tempogate/oidc/google"
	"github.com/onhotpath/tempogate/state/sqlite"
)

// TokenE2ESuite exercises the whole authorization-code flow against the real
// HTTP surface: /authorize → (mock Google) → /callback/google → /token, with
// a real sqlite store, real signing keys, and the access token verified
// against the JWKS the server actually publishes. No fakes for the store,
// the signer, or the verification path.
// e2eConfidentialSecret is the shared secret for the older-style confidential
// client the no-PKCE flow exercises (the Temporal Web UI's class of client).
const e2eConfidentialSecret = "e2e-confidential-secret"

type TokenE2ESuite struct {
	suite.Suite

	mg     *mockGoogle
	store  *sqlite.Store
	srv    *httptest.Server
	client *http.Client
}

func TestTokenE2ESuite(t *testing.T) {
	suite.Run(t, new(TokenE2ESuite))
}

func (s *TokenE2ESuite) SetupTest() {
	ctx := context.Background()

	store, err := sqlite.New(sqlite.WithPath(filepath.Join(s.T().TempDir(), "e2e.db")))
	s.Require().NoError(err)
	s.Require().NoError(store.Migrate(ctx))
	s.T().Cleanup(func() { _ = store.Close() })
	s.store = store

	k := keys.New(keys.WithStore(store), keys.WithGenerateOptions(keys.WithRSABits(2048)))
	s.Require().NoError(k.Init(ctx))
	signer := keys.NewSigner(keys.WithKeys(k), keys.WithIssuer(testIssuer))

	s.mg = newMockGoogle(s.T(), testGoogleCID, "alice@example.com", true)
	upstream := google.New(
		s.mg.clientID,
		"mock-secret",
		s.mg.issuer()+"/token",
		testIssuer+oidc.CallbackPath,
		s.mg.issuer(),
	)

	reg, err := oidc.ParseClientRegistry("ui:https://app.example.com/auth,webui:https://app.example.com/auth,tempogate-device:cli")
	s.Require().NoError(err)
	s.Require().NoError(reg.WithSecrets("webui:" + e2eConfidentialSecret))

	authorizer := oidc.New(store, reg, testIssuer, testGoogleCID, s.mg.issuer()+"/auth")
	callback := oidc.NewCallback(store, upstream, "example.com")
	token := oidc.NewToken(store, signer, reg, oidc.WithDeviceCodeStore(store))
	userinfo := oidc.NewUserInfo(keys.NewVerifier(keys.WithKeys(k), keys.WithIssuer(testIssuer)))
	device := oidc.NewDeviceAuthorization(store, reg, testIssuer)

	result := api.New(api.NewReadiness(),
		api.WithWellKnown(k, testIssuer),
		api.WithRegistrar(authorizer.Register),
		api.WithRegistrar(callback.Register),
		api.WithRegistrar(token.Register),
		api.WithRegistrar(userinfo.Register),
		api.WithRegistrar(device.Register),
	)
	s.srv = httptest.NewServer(result.Public.Handler)
	s.T().Cleanup(s.srv.Close)

	s.client = &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// runFlow drives /authorize and /callback/google and returns the
// authorization code the browser would carry back to the downstream client.
func (s *TokenE2ESuite) runFlow() string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", "ui")
	q.Set("redirect_uri", testRedirectURI)
	q.Set("scope", "openid email")
	q.Set("state", "client-state-xyz")
	q.Set("code_challenge", pkceChallenge)
	q.Set("code_challenge_method", "S256")

	authResp, err := s.client.Get(s.srv.URL + "/authorize?" + q.Encode())
	s.Require().NoError(err)
	authResp.Body.Close()
	s.Require().Equal(http.StatusFound, authResp.StatusCode)

	toGoogle, err := url.Parse(authResp.Header.Get("Location"))
	s.Require().NoError(err)
	internalState := toGoogle.Query().Get("state")
	s.Require().NotEmpty(internalState)

	cbResp, err := s.client.Get(s.srv.URL + "/callback/google?code=real-google-code&state=" + internalState)
	s.Require().NoError(err)
	cbResp.Body.Close()
	s.Require().Equal(http.StatusFound, cbResp.StatusCode)

	backToClient, err := url.Parse(cbResp.Header.Get("Location"))
	s.Require().NoError(err)
	s.Equal("client-state-xyz", backToClient.Query().Get("state"))
	code := backToClient.Query().Get("code")
	s.Require().NotEmpty(code)
	return code
}

func (s *TokenE2ESuite) tokenRequest(form url.Values) *http.Response {
	resp, err := s.client.Post(s.srv.URL+"/token",
		"application/x-www-form-urlencoded",
		strings.NewReader(form.Encode()))
	s.Require().NoError(err)
	return resp
}

// jwksSet fetches the JWKS the server publishes and parses it into a key set
// usable for signature verification — the exact path a relying party
// (Temporal frontend) would take.
func (s *TokenE2ESuite) jwksSet() jwk.Set {
	resp, err := s.client.Get(s.srv.URL + "/.well-known/jwks.json")
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusOK, resp.StatusCode)

	set, err := jwk.ParseReader(resp.Body)
	s.Require().NoError(err)
	s.Require().Positive(set.Len())
	return set
}

func (s *TokenE2ESuite) decode(resp *http.Response) struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
} {
	var b struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
	}
	s.Require().NoError(json.NewDecoder(resp.Body).Decode(&b))
	return b
}

func (s *TokenE2ESuite) TestFullFlowMintsJWTVerifiableAgainstPublishedJWKS() {
	code := s.runFlow()

	f := url.Values{}
	f.Set("grant_type", "authorization_code")
	f.Set("code", code)
	f.Set("redirect_uri", testRedirectURI)
	f.Set("client_id", "ui")
	f.Set("code_verifier", pkceVerifier)

	resp := s.tokenRequest(f)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusOK, resp.StatusCode)

	body := s.decode(resp)
	s.Equal("Bearer", body.TokenType)
	s.Equal(14400, body.ExpiresIn)
	s.Equal(body.AccessToken, body.IDToken)
	s.Require().NotEmpty(body.RefreshToken)

	tok, err := jwt.Parse([]byte(body.AccessToken),
		jwt.WithKeySet(s.jwksSet()),
		jwt.WithIssuer(testIssuer),
	)
	s.Require().NoError(err, "JWT must verify against the published JWKS")

	sub, ok := tok.Subject()
	s.Require().True(ok)
	s.Equal("alice@example.com", sub)

	perms, ok := tok.Field("permissions")
	s.Require().True(ok)
	s.Equal([]string{"temporal-system:admin"}, toStringSlice(s.T(), perms))

	exp, ok := tok.Expiration()
	s.Require().True(ok)
	iat, ok := tok.IssuedAt()
	s.Require().True(ok)
	s.InDelta(float64(4*time.Hour), float64(exp.Sub(iat)), float64(time.Second))

	// /userinfo closes the OIDC loop: the same access token authenticates
	// the call and yields the session's display claims.
	uiReq, err := http.NewRequest(http.MethodGet, s.srv.URL+"/userinfo", http.NoBody)
	s.Require().NoError(err)
	uiReq.Header.Set("Authorization", "Bearer "+body.AccessToken)
	uiResp, err := s.client.Do(uiReq)
	s.Require().NoError(err)
	defer uiResp.Body.Close()
	s.Require().Equal(http.StatusOK, uiResp.StatusCode)

	var ui struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
	}
	s.Require().NoError(json.NewDecoder(uiResp.Body).Decode(&ui))
	s.Equal("alice@example.com", ui.Sub)
	s.Equal("alice@example.com", ui.Email)
	s.True(ui.EmailVerified)
	s.Equal("alice", ui.Name)

	// Refresh-token grant: a new, equally valid JWT against the same JWKS.
	rf := url.Values{}
	rf.Set("grant_type", "refresh_token")
	rf.Set("refresh_token", body.RefreshToken)
	rResp := s.tokenRequest(rf)
	defer rResp.Body.Close()
	s.Require().Equal(http.StatusOK, rResp.StatusCode)

	rBody := s.decode(rResp)
	s.NotEqual(body.RefreshToken, rBody.RefreshToken, "refresh token must rotate")
	rTok, err := jwt.Parse([]byte(rBody.AccessToken),
		jwt.WithKeySet(s.jwksSet()),
		jwt.WithIssuer(testIssuer),
	)
	s.Require().NoError(err)
	rPerms, ok := rTok.Field("permissions")
	s.Require().True(ok)
	s.Equal([]string{"temporal-system:admin"}, toStringSlice(s.T(), rPerms))
}

func (s *TokenE2ESuite) TestConsumedCodeCannotBeReplayed() {
	code := s.runFlow()
	f := url.Values{}
	f.Set("grant_type", "authorization_code")
	f.Set("code", code)
	f.Set("redirect_uri", testRedirectURI)
	f.Set("client_id", "ui")
	f.Set("code_verifier", pkceVerifier)

	first := s.tokenRequest(f)
	first.Body.Close()
	s.Require().Equal(http.StatusOK, first.StatusCode)

	second := s.tokenRequest(f)
	defer second.Body.Close()
	s.Equal(http.StatusBadRequest, second.StatusCode)
}

func (s *TokenE2ESuite) TestPKCEMismatchRejectedEndToEnd() {
	code := s.runFlow()
	f := url.Values{}
	f.Set("grant_type", "authorization_code")
	f.Set("code", code)
	f.Set("redirect_uri", testRedirectURI)
	f.Set("client_id", "ui")
	f.Set("code_verifier", "not-the-verifier-that-hashes-to-the-challenge")

	resp := s.tokenRequest(f)
	defer resp.Body.Close()
	s.Equal(http.StatusBadRequest, resp.StatusCode)
}

// runConfidentialFlow drives /authorize → mock Google → /callback for the
// confidential client: no PKCE challenge, a nonce instead — exactly the shape
// the Temporal Web UI's OIDC client produces. It returns the auth code.
func (s *TokenE2ESuite) runConfidentialFlow(nonce string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", "webui")
	q.Set("redirect_uri", testRedirectURI)
	q.Set("scope", "openid email")
	q.Set("state", "client-state-conf")
	q.Set("nonce", nonce)

	authResp, err := s.client.Get(s.srv.URL + "/authorize?" + q.Encode())
	s.Require().NoError(err)
	authResp.Body.Close()
	s.Require().Equal(http.StatusFound, authResp.StatusCode,
		"confidential client must clear /authorize with no PKCE challenge")

	toGoogle, err := url.Parse(authResp.Header.Get("Location"))
	s.Require().NoError(err)
	internalState := toGoogle.Query().Get("state")
	s.Require().NotEmpty(internalState)

	cbResp, err := s.client.Get(s.srv.URL + "/callback/google?code=real-google-code&state=" + internalState)
	s.Require().NoError(err)
	cbResp.Body.Close()
	s.Require().Equal(http.StatusFound, cbResp.StatusCode)

	backToClient, err := url.Parse(cbResp.Header.Get("Location"))
	s.Require().NoError(err)
	code := backToClient.Query().Get("code")
	s.Require().NotEmpty(code)
	return code
}

// TestConfidentialNoPKCEFlowMintsNonceAudJWT is the unit-level proof of the
// whole Temporal-Web-UI interop: a confidential client completes the flow
// without PKCE, authenticates at /token with HTTP Basic, and the minted JWT
// verifies against the published JWKS with iss + aud(=client_id) + nonce —
// the exact checks go-oidc performs inside the real UI.
func (s *TokenE2ESuite) TestConfidentialNoPKCEFlowMintsNonceAudJWT() {
	const nonce = "ui-supplied-nonce-123"
	code := s.runConfidentialFlow(nonce)

	f := url.Values{}
	f.Set("grant_type", "authorization_code")
	f.Set("code", code)
	f.Set("redirect_uri", testRedirectURI)
	// client_id + secret travel in the Basic header, as x/oauth2 sends them.
	req, err := http.NewRequest(http.MethodPost, s.srv.URL+"/token", strings.NewReader(f.Encode()))
	s.Require().NoError(err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape("webui"), url.QueryEscape(e2eConfidentialSecret))
	resp, err := s.client.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusOK, resp.StatusCode)

	body := s.decode(resp)
	tok, err := jwt.Parse([]byte(body.IDToken),
		jwt.WithKeySet(s.jwksSet()),
		jwt.WithIssuer(testIssuer),
		jwt.WithAudience("webui"),
	)
	s.Require().NoError(err, "JWT must verify with iss + aud=client_id, as the Temporal UI's go-oidc does")

	gotNonce, ok := tok.Field("nonce")
	s.Require().True(ok)
	s.Equal(nonce, gotNonce, "nonce must round-trip so the UI's idToken.Nonce check passes")

	perms, ok := tok.Field("permissions")
	s.Require().True(ok)
	s.Equal([]string{"temporal-system:admin"}, toStringSlice(s.T(), perms))

	// A wrong secret on the same flow is rejected as invalid_client.
	code2 := s.runConfidentialFlow(nonce)
	f2 := url.Values{}
	f2.Set("grant_type", "authorization_code")
	f2.Set("code", code2)
	f2.Set("redirect_uri", testRedirectURI)
	f2.Set("client_id", "webui")
	f2.Set("client_secret", "wrong")
	bad := s.tokenRequest(f2)
	defer bad.Body.Close()
	s.Equal(http.StatusUnauthorized, bad.StatusCode)
}

// TestDeviceCodeFlowMintsJWTVerifiableAgainstPublishedJWKS proves the whole
// RFC 8628 round-trip end-to-end against a real sqlite store and the JWKS
// the server actually publishes: POST /device_authorization mints a row, an
// out-of-band Approve stamps it (standing in for the verification-page UI
// the next epic stage delivers), and POST /token with grant_type=device_code
// yields a JWT that verifies against the same JWKS the auth-code path does —
// with the device-flow carve-out that nonce is absent.
func (s *TokenE2ESuite) TestDeviceCodeFlowMintsJWTVerifiableAgainstPublishedJWKS() {
	// §3.1: CLI initiates the flow.
	daResp, err := s.client.Post(s.srv.URL+"/device_authorization",
		"application/x-www-form-urlencoded",
		strings.NewReader("client_id=tempogate-device&scope=openid+email"))
	s.Require().NoError(err)
	defer daResp.Body.Close()
	s.Require().Equal(http.StatusOK, daResp.StatusCode)

	var da struct {
		DeviceCode string `json:"device_code"`
		UserCode   string `json:"user_code"`
		Interval   int    `json:"interval"`
	}
	s.Require().NoError(json.NewDecoder(daResp.Body).Decode(&da))
	s.Require().NotEmpty(da.DeviceCode)

	// Stand in for the verification UI: Approve the row directly through the
	// store. (The UI lands in the next epic stage; the contract under test
	// here is the /token branch and the store-level transition.) The pending
	// and slow_down state-machine branches are exercised by sibling tests —
	// here we want the success path uncluttered by interval-window timing.
	canonical := strings.ReplaceAll(da.UserCode, "-", "")
	s.Require().NoError(s.store.ApproveDeviceCode(context.Background(), canonical, "alice@example.com", time.Now().UTC()))

	// Approved poll: the row is consumed and a fresh JWT comes back.
	resp := s.deviceTokenPoll(da.DeviceCode)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusOK, resp.StatusCode)
	body := s.decode(resp)
	s.Equal("Bearer", body.TokenType)
	s.Equal(14400, body.ExpiresIn)
	s.Equal(body.AccessToken, body.IDToken)
	s.Require().NotEmpty(body.RefreshToken)

	tok, err := jwt.Parse([]byte(body.AccessToken),
		jwt.WithKeySet(s.jwksSet()),
		jwt.WithIssuer(testIssuer),
	)
	s.Require().NoError(err, "device-code JWT must verify against the same JWKS the auth-code JWT does")

	sub, ok := tok.Subject()
	s.Require().True(ok)
	s.Equal("alice@example.com", sub)
	aud, _ := tok.Audience()
	s.Equal([]string{"tempogate-device"}, aud)
	perms, _ := tok.Field("permissions")
	s.Equal([]string{"temporal-system:admin"}, toStringSlice(s.T(), perms))
	_, hasNonce := tok.Field("nonce")
	s.False(hasNonce, "device-code flow has no nonce concept")

	// Row was atomically consumed: a follow-up poll is invalid_grant —
	// asserting the OAuth error code as well as the status guards against a
	// regression to slow_down or any other 400 family that would also pass a
	// status-only check.
	again := s.deviceTokenPoll(da.DeviceCode)
	defer again.Body.Close()
	s.Equal(http.StatusBadRequest, again.StatusCode)
	var againErr struct {
		Error string `json:"error"`
	}
	s.Require().NoError(json.NewDecoder(again.Body).Decode(&againErr))
	s.Equal("invalid_grant", againErr.Error)
}

// TestDeviceCodeFlowSlowDownBumpsServerInterval drives the slow_down rule
// against the real store: two rapid polls before any Approve land within the
// same interval window, so the second returns slow_down and the row's
// interval_seconds has been bumped from the seeded 5 to 10.
func (s *TokenE2ESuite) TestDeviceCodeFlowSlowDownBumpsServerInterval() {
	daResp, err := s.client.Post(s.srv.URL+"/device_authorization",
		"application/x-www-form-urlencoded",
		strings.NewReader("client_id=tempogate-device"))
	s.Require().NoError(err)
	defer daResp.Body.Close()
	s.Require().Equal(http.StatusOK, daResp.StatusCode)

	var da struct {
		DeviceCode string `json:"device_code"`
	}
	s.Require().NoError(json.NewDecoder(daResp.Body).Decode(&da))

	// Two polls back-to-back; the second is within the 5s window.
	first := s.deviceTokenPoll(da.DeviceCode)
	first.Body.Close()
	s.Require().Equal(http.StatusBadRequest, first.StatusCode)

	second := s.deviceTokenPoll(da.DeviceCode)
	defer second.Body.Close()
	s.Require().Equal(http.StatusBadRequest, second.StatusCode)

	var errBody struct {
		Error string `json:"error"`
	}
	s.Require().NoError(json.NewDecoder(second.Body).Decode(&errBody))
	s.Equal("slow_down", errBody.Error)

	row, err := s.store.LookupDeviceCodeByDeviceCode(context.Background(), da.DeviceCode)
	s.Require().NoError(err)
	s.Equal(10, row.IntervalSeconds, "slow_down must persist the +5s bump through the real sqlite store")
}

// deviceTokenPoll is the CLI's wire-level poll: form-encoded
// grant_type=urn:..., device_code, client_id.
func (s *TokenE2ESuite) deviceTokenPoll(deviceCode string) *http.Response {
	f := url.Values{}
	f.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	f.Set("device_code", deviceCode)
	f.Set("client_id", "tempogate-device")
	return s.tokenRequest(f)
}
