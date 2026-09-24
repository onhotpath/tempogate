package oidc_test

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
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

// DeviceUIIntegrationSuite exercises the whole RFC 8628 verification flow
// against the real HTTP surface — POST /device_authorization, the human-
// side bounce through /authorize → mock Google → /callback/google →
// /device/sso-callback → /device/confirm → POST /device/approve, then the
// CLI's /token device-code poll redeems the now-approved row. Every
// component is real: sqlite store, RSA signer, JWKS verification. The
// mock IdP stands in only for the upstream Google leg, the same boundary
// the auth-code e2e suite mocks.
type DeviceUIIntegrationSuite struct {
	suite.Suite

	mg      *mockGoogle
	store   *sqlite.Store
	signKey []byte
	issuer  string
	srv     *httptest.Server
	browser *http.Client
	cli     *http.Client
}

func TestDeviceUIIntegrationSuite(t *testing.T) {
	suite.Run(t, new(DeviceUIIntegrationSuite))
}

func (s *DeviceUIIntegrationSuite) SetupTest() {
	ctx := context.Background()

	store, err := sqlite.New(sqlite.WithPath(filepath.Join(s.T().TempDir(), "device-ui-e2e.db")))
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

	clients := "tempogate-device:cli,tempogate-device-ui:" + testIssuer + "/device/sso-callback"
	reg, err := oidc.ParseClientRegistry(clients)
	s.Require().NoError(err)
	s.Require().NoError(reg.WithSecrets("tempogate-device-ui:" + deviceUIInternalSecret))

	s.signKey = []byte("0123456789abcdef0123456789abcdef")
	s.issuer = testIssuer
	// The integration server is httptest TLS without a /idp base path; the
	// production default cookie path "/idp/device" therefore would not
	// match any test request. Widening to "/" keeps the same Secure +
	// HttpOnly attributes the cookie ships with in production while
	// letting the jar return the cookie on every request the bounce
	// touches.
	sessions := oidc.NewSessionManager(store, s.signKey,
		oidc.WithSessionTTL(5*time.Minute),
		oidc.WithCookiePath("/"),
	)

	authorizer := oidc.New(store, reg, s.issuer, testGoogleCID, s.mg.issuer()+"/auth")
	callback := oidc.NewCallback(store, upstream, "example.com")
	token := oidc.NewToken(store, signer, reg, oidc.WithDeviceCodeStore(store))
	deviceAuth := oidc.NewDeviceAuthorization(store, reg, s.issuer)

	// The integration server is httptest TLS so the production cookie
	// attribute set (Secure + HttpOnly + SameSite=Lax) is exercised
	// faithfully — Secure cookies require an https origin for the jar to
	// send them back. The mock upstream IdP runs on a separate
	// httptest.NewServer (plain http on 127.0.0.1) from the tempogate test
	// server (TLS on a different port) — i.e., a different origin from the
	// issuer. This is the same cross-origin shape every production Google
	// deployment has, and is what triggered the CSP form-action regression
	// the upstream-origin option in the device-ui pins. Wiring the
	// upstream auth endpoint here so the device_enter page's CSP
	// whitelists that origin is what lets the post-submit redirect chain
	// reach the IdP.
	//
	// DeviceUI hands the SSO-callback auth-code redemption to the shared
	// *Token in-process — no loopback HTTPS POST back to its own /token
	// endpoint, so the integration suite no longer needs a tokenURL or a
	// trust-store-relaxed HTTP client for that hop.
	deviceUI, err := oidc.NewDeviceUI(store, sessions, reg, token, s.signKey, s.issuer,
		oidc.WithUpstreamIDPOrigin(s.mg.issuer()+"/auth"),
	)
	s.Require().NoError(err)

	result := api.New(api.NewReadiness(),
		api.WithWellKnown(k, s.issuer),
		api.WithRegistrar(authorizer.Register),
		api.WithRegistrar(callback.Register),
		api.WithRegistrar(token.Register),
		api.WithRegistrar(deviceAuth.Register),
		api.WithRegistrar(deviceUI.Register),
	)
	srv := httptest.NewUnstartedServer(result.Public.Handler)
	srv.StartTLS()
	s.T().Cleanup(srv.Close)
	s.srv = srv

	// Two clients: `browser` follows the human-side redirects with a
	// cookie jar so the session cookie sticks across the bounce. `cli`
	// stands in for the polling CLI — no jar. Both trust the httptest
	// self-signed cert because the test server is the only TLS peer.
	jar, err := cookiejar.New(nil)
	s.Require().NoError(err)
	s.browser = &http.Client{
		Jar:           jar,
		Transport:     insecureTLSTransport(),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	s.cli = &http.Client{Transport: insecureTLSTransport()}
}

// TestFullDeviceFlowAgainstRealStack walks the entire RFC 8628 flow:
//
//  1. CLI: POST /device_authorization → device_code, user_code.
//  2. Human: GET /device → POST user_code → 303 /authorize.
//  3. /authorize → mock Google → /callback/google → 302 to
//     /device/sso-callback.
//  4. /device/sso-callback redeems the auth code in-process via the
//     shared *Token, mints a session cookie, 303 to /device/confirm.
//  5. Human: GET /device/confirm → renders the Approve form.
//  6. Human: POST /device/approve → row flipped, success page rendered.
//  7. CLI: POST /token (device_code grant) → JWT for the authenticated
//     user verifies against the published JWKS.
func (s *DeviceUIIntegrationSuite) TestFullDeviceFlowAgainstRealStack() {
	ctx := context.Background()

	daResp, err := s.cli.Post(s.srv.URL+"/device_authorization",
		"application/x-www-form-urlencoded",
		strings.NewReader("client_id=tempogate-device&scope=openid+email"))
	s.Require().NoError(err)
	defer daResp.Body.Close()
	s.Require().Equal(http.StatusOK, daResp.StatusCode)

	var da struct {
		DeviceCode string `json:"device_code"`
		UserCode   string `json:"user_code"`
	}
	s.Require().NoError(json.NewDecoder(daResp.Body).Decode(&da))
	s.Require().NotEmpty(da.DeviceCode)
	s.Require().NotEmpty(da.UserCode)

	enterResp, err := s.browser.Get(s.srv.URL + "/device")
	s.Require().NoError(err)
	enterResp.Body.Close()
	s.Require().Equal(http.StatusOK, enterResp.StatusCode)

	postResp, err := s.browser.PostForm(s.srv.URL+"/device", url.Values{"user_code": {da.UserCode}})
	s.Require().NoError(err)
	postResp.Body.Close()
	s.Require().Equal(http.StatusSeeOther, postResp.StatusCode,
		"no-session POST must 303 through the upstream IdP bounce")
	authorizeURL, err := url.Parse(postResp.Header.Get("Location"))
	s.Require().NoError(err)
	s.Equal("/authorize", authorizeURL.Path)
	s.Equal("tempogate-device-ui", authorizeURL.Query().Get("client_id"))
	bounceState := authorizeURL.Query().Get("state")
	s.Require().NotEmpty(bounceState)

	authResp, err := s.browser.Get(s.srv.URL + authorizeURL.RequestURI())
	s.Require().NoError(err)
	authResp.Body.Close()
	s.Require().Equal(http.StatusFound, authResp.StatusCode)
	toGoogle, err := url.Parse(authResp.Header.Get("Location"))
	s.Require().NoError(err)
	internalState := toGoogle.Query().Get("state")
	s.Require().NotEmpty(internalState)

	cbResp, err := s.browser.Get(s.srv.URL + "/callback/google?code=real-google-code&state=" + internalState)
	s.Require().NoError(err)
	cbResp.Body.Close()
	s.Require().Equal(http.StatusFound, cbResp.StatusCode)
	toDevice, err := url.Parse(cbResp.Header.Get("Location"))
	s.Require().NoError(err)
	s.Equal("/device/sso-callback", toDevice.Path)
	s.Equal(bounceState, toDevice.Query().Get("state"),
		"bounce state must round-trip unchanged through the /authorize chain")

	ssoResp, err := s.browser.Get(s.srv.URL + toDevice.RequestURI())
	s.Require().NoError(err)
	ssoResp.Body.Close()
	s.Require().Equal(http.StatusSeeOther, ssoResp.StatusCode)
	toConfirm, err := url.Parse(ssoResp.Header.Get("Location"))
	s.Require().NoError(err)
	s.Equal("/device/confirm", toConfirm.Path)
	s.Equal(da.UserCode, toConfirm.Query().Get("user_code"))

	confirmResp, err := s.browser.Get(s.srv.URL + toConfirm.RequestURI())
	s.Require().NoError(err)
	defer confirmResp.Body.Close()
	s.Require().Equal(http.StatusOK, confirmResp.StatusCode)
	confirmBody := readBody(s.T(), confirmResp)
	s.Contains(confirmBody, da.UserCode)
	s.Contains(confirmBody, "alice@example.com")

	sid := s.sessionSID()
	s.Require().NotEmpty(sid, "session cookie must be present after sso-callback")

	approveBody := url.Values{"csrf_token": {sid}, "user_code": {da.UserCode}}
	approveReq, err := http.NewRequest(http.MethodPost, s.srv.URL+"/device/approve", strings.NewReader(approveBody.Encode()))
	s.Require().NoError(err)
	approveReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	approveReq.Header.Set("Origin", s.issuer)
	approveResp, err := s.browser.Do(approveReq)
	s.Require().NoError(err)
	defer approveResp.Body.Close()
	s.Require().Equal(http.StatusOK, approveResp.StatusCode)
	s.Contains(readBody(s.T(), approveResp), "Device approved")

	canonical := strings.ReplaceAll(da.UserCode, "-", "")
	row, err := s.store.LookupDeviceCodeByUserCode(ctx, canonical)
	s.Require().NoError(err)
	s.Require().NotNil(row.ApprovedAt, "ApproveDeviceCode must have stamped the row")
	s.Equal("alice@example.com", row.Email)

	f := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {da.DeviceCode},
		"client_id":   {"tempogate-device"},
	}
	tokResp, err := s.cli.Post(s.srv.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader(f.Encode()))
	s.Require().NoError(err)
	defer tokResp.Body.Close()
	s.Require().Equal(http.StatusOK, tokResp.StatusCode)

	var tok struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	s.Require().NoError(json.NewDecoder(tokResp.Body).Decode(&tok))
	s.Equal("Bearer", tok.TokenType)

	jwksResp, err := s.cli.Get(s.srv.URL + "/.well-known/jwks.json")
	s.Require().NoError(err)
	defer jwksResp.Body.Close()
	keySet, err := jwk.ParseReader(jwksResp.Body)
	s.Require().NoError(err)

	parsed, err := jwt.Parse([]byte(tok.AccessToken),
		jwt.WithKeySet(keySet),
		jwt.WithIssuer(s.issuer),
	)
	s.Require().NoError(err)
	sub, ok := parsed.Subject()
	s.Require().True(ok)
	s.Equal("alice@example.com", sub)
}

// TestDenyFlipsRowAndDeviceCodePollSeesAccessDenied exercises the deny
// path end-to-end: the human denies, the row is stamped denied, and the
// CLI's device-code poll surfaces access_denied per RFC 8628 §3.5.
func (s *DeviceUIIntegrationSuite) TestDenyFlipsRowAndDeviceCodePollSeesAccessDenied() {
	daResp, err := s.cli.Post(s.srv.URL+"/device_authorization",
		"application/x-www-form-urlencoded",
		strings.NewReader("client_id=tempogate-device"))
	s.Require().NoError(err)
	defer daResp.Body.Close()
	var da struct {
		DeviceCode string `json:"device_code"`
		UserCode   string `json:"user_code"`
	}
	s.Require().NoError(json.NewDecoder(daResp.Body).Decode(&da))

	s.driveThroughConfirm(da.UserCode)

	sid := s.sessionSID()
	s.Require().NotEmpty(sid)

	denyForm := url.Values{"csrf_token": {sid}, "user_code": {da.UserCode}}
	req, err := http.NewRequest(http.MethodPost, s.srv.URL+"/device/deny", strings.NewReader(denyForm.Encode()))
	s.Require().NoError(err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", s.issuer)
	denyResp, err := s.browser.Do(req)
	s.Require().NoError(err)
	defer denyResp.Body.Close()
	s.Require().Equal(http.StatusOK, denyResp.StatusCode)
	s.Contains(readBody(s.T(), denyResp), "Device denied")

	f := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {da.DeviceCode},
		"client_id":   {"tempogate-device"},
	}
	pollResp, err := s.cli.Post(s.srv.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader(f.Encode()))
	s.Require().NoError(err)
	defer pollResp.Body.Close()
	s.Require().Equal(http.StatusBadRequest, pollResp.StatusCode)
	var oauthErr struct {
		Error string `json:"error"`
	}
	s.Require().NoError(json.NewDecoder(pollResp.Body).Decode(&oauthErr))
	s.Equal("access_denied", oauthErr.Error)
}

// TestEnterPageCSPAllowsCrossOriginUpstreamIDP is the regression guard
// for the CSP3 form-action footgun: the verification page must include
// the upstream IdP's origin in its form-action source list, because the
// directive is enforced across every URL in the redirect chain a form
// submission produces (POST /device → 303 /authorize → 302 upstream).
// Without this source, a real browser silently refuses the cross-origin
// hop and the device flow stalls on the entry form. Go's http.Client
// does not enforce CSP, so the prior end-to-end happy-path tests do not
// catch the regression on their own — this test asserts the directive's
// rendered shape directly.
func (s *DeviceUIIntegrationSuite) TestEnterPageCSPAllowsCrossOriginUpstreamIDP() {
	upstreamOrigin, err := url.Parse(s.mg.issuer())
	s.Require().NoError(err)
	wantSource := upstreamOrigin.Scheme + "://" + upstreamOrigin.Host
	s.Require().NotEqual(s.issuer, wantSource,
		"sanity: mock IdP must be on a different origin from the issuer for this test to be meaningful")

	resp, err := s.browser.Get(s.srv.URL + "/device")
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusOK, resp.StatusCode)

	body := readBody(s.T(), resp)
	s.Contains(body, "form-action 'self' "+wantSource+";",
		"the entry page CSP must whitelist the upstream IdP's origin in its form-action directive")
}

// driveThroughConfirm walks GET /device → POST /device → /authorize →
// mock Google → /callback/google → /device/sso-callback → /device/confirm,
// stopping after the session cookie is established and the confirm page
// has rendered. Tests that exercise approve/deny share this driver to
// keep their bodies focused on the leg they actually assert.
func (s *DeviceUIIntegrationSuite) driveThroughConfirm(userCode string) {
	enterResp, err := s.browser.Get(s.srv.URL + "/device")
	s.Require().NoError(err)
	enterResp.Body.Close()

	postResp, err := s.browser.PostForm(s.srv.URL+"/device", url.Values{"user_code": {userCode}})
	s.Require().NoError(err)
	postResp.Body.Close()
	s.Require().Equal(http.StatusSeeOther, postResp.StatusCode)
	authorizeURL, err := url.Parse(postResp.Header.Get("Location"))
	s.Require().NoError(err)

	authResp, err := s.browser.Get(s.srv.URL + authorizeURL.RequestURI())
	s.Require().NoError(err)
	authResp.Body.Close()
	toGoogle, err := url.Parse(authResp.Header.Get("Location"))
	s.Require().NoError(err)
	internalState := toGoogle.Query().Get("state")

	cbResp, err := s.browser.Get(s.srv.URL + "/callback/google?code=real-google-code&state=" + internalState)
	s.Require().NoError(err)
	cbResp.Body.Close()
	toDevice, err := url.Parse(cbResp.Header.Get("Location"))
	s.Require().NoError(err)

	ssoResp, err := s.browser.Get(s.srv.URL + toDevice.RequestURI())
	s.Require().NoError(err)
	ssoResp.Body.Close()
	toConfirm, err := url.Parse(ssoResp.Header.Get("Location"))
	s.Require().NoError(err)

	confirmResp, err := s.browser.Get(s.srv.URL + toConfirm.RequestURI())
	s.Require().NoError(err)
	confirmResp.Body.Close()
	s.Require().Equal(http.StatusOK, confirmResp.StatusCode)
}

// insecureTLSTransport trusts any TLS peer — fine here because the only
// peer is the suite's own httptest server. Pulled into a helper so both
// the browser and CLI test clients share the same setting.
func insecureTLSTransport() *http.Transport {
	return &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // test-only loopback peer
}

// sessionSID extracts the opaque sid out of the SessionManager cookie the
// browser jar carries. The cookie's value is base64url(sid).base64url(mac);
// the test forges the CSRF token by quoting the sid back into the Approve
// / Deny POST, so it inverts the encoding without importing the production
// signCookie helper.
func (s *DeviceUIIntegrationSuite) sessionSID() string {
	srvURL, err := url.Parse(s.srv.URL)
	s.Require().NoError(err)
	for _, c := range s.browser.Jar.Cookies(srvURL) {
		if c.Name != "tempogate_session" {
			continue
		}
		parts := strings.SplitN(c.Value, ".", 2)
		if len(parts) != 2 {
			return ""
		}
		raw, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			return ""
		}
		return string(raw)
	}
	return ""
}
