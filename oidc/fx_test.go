package oidc_test

import (
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/stretchr/testify/suite"
	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"

	"github.com/onhotpath/tempogate/keys"
	"github.com/onhotpath/tempogate/oidc"
)

var testSigningKeyB64 = base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))

// deviceUIFxClients is the canonical clients string the FxSuite uses to
// satisfy the device-ui registrar's internal-client requirement on top of
// the regular `ui` + `tempogate-device` registrations. Each test that
// drives the graph successfully composes this with the matching secret in
// supplyConfig*.
const deviceUIFxClients = "ui:https://app.example.com/auth,tempogate-device:,tempogate-device-ui:" + testIssuer + "/device/sso-callback"

type FxSuite struct {
	suite.Suite

	// lifetimes feed the OIDC_*_TTL / OIDC_REFRESH_MAX_LIFETIME annotations;
	// SetupTest resets them to the defaults so only the validation test
	// varies them.
	accessTTL, refreshTTL, refreshMax time.Duration
}

func (s *FxSuite) SetupTest() {
	s.accessTTL = oidc.DefaultAccessTokenTTL
	s.refreshTTL = oidc.DefaultRefreshTokenTTL
	s.refreshMax = oidc.DefaultRefreshMaxLifetime
}

func TestFxSuite(t *testing.T) {
	suite.Run(t, new(FxSuite))
}

func (s *FxSuite) supplyConfig(clients string) fx.Option {
	return s.supplyConfigFull(clients, "tempogate-device-ui:"+deviceUIInternalSecret, testSigningKeyB64, false)
}

func (s *FxSuite) supplyConfigWithSessionKey(clients, signingKeyB64 string) fx.Option {
	return s.supplyConfigFull(clients, "tempogate-device-ui:"+deviceUIInternalSecret, signingKeyB64, false)
}

// supplyConfigFull is the underlying knob the suite's helpers compose on.
// It exists so a small number of tests — the device-ui graph-failure
// regression guards — can vary the secrets independently of the clients
// list (or the insecure-redirect flag) without forcing every other test to
// plumb the extra arguments.
func (s *FxSuite) supplyConfigFull(clients, secrets, signingKeyB64 string, allowInsecureRedirectURIs bool) fx.Option {
	return s.supplyConfigAt(testIssuer, "", clients, secrets, signingKeyB64, allowInsecureRedirectURIs)
}

// supplyConfigAt additionally varies the issuer and the base path config
// projects from it, for the wiring that derives behaviour from the issuer.
func (s *FxSuite) supplyConfigAt(issuer, basePath, clients, secrets, signingKeyB64 string, allowInsecureRedirectURIs bool) fx.Option {
	return fx.Options(
		fx.Provide(func() oidc.AuthRequestStore { return &memAuthStore{} }),
		fx.Provide(func() oidc.BrowserSessionStore { return newMemBrowserSessionStore() }),
		fx.Provide(func() oidc.CallbackStore { return &memCallbackStore{} }),
		fx.Provide(func() oidc.TokenStore { return newMemTokenStore() }),
		fx.Provide(func() oidc.DeviceCodeStore { return &memDeviceCodeStore{} }),
		fx.Provide(func() oidc.Upstream { return &fakeUpstream{} }),
		fx.Provide(func() *keys.Signer { return keys.NewSigner() }),
		fx.Provide(func() *keys.Verifier { return keys.NewVerifier() }),
		// Discard-handler logger satisfies the DeviceUI logger dependency
		// the production fx graph wires from the log package. The fx-graph
		// regression guards in this suite assert wiring shape, not log
		// output — those assertions live in device_ui_test.go.
		fx.Provide(func() *slog.Logger { return slog.New(slog.DiscardHandler) }),
		fx.Supply(
			fx.Annotated{Name: "oidc_issuer", Target: issuer},
			fx.Annotated{Name: "oidc_base_path", Target: basePath},
			fx.Annotated{Name: "oidc_clients", Target: clients},
			fx.Annotated{Name: "oidc_client_secrets", Target: secrets},
			fx.Annotated{Name: "oidc_allow_insecure_redirect_uris", Target: allowInsecureRedirectURIs},
			fx.Annotated{Name: "oidc_allowed_domains", Target: "example.com"},
			fx.Annotated{Name: "oidc_session_ttl", Target: 5 * time.Minute},
			fx.Annotated{Name: "oidc_session_signing_key", Target: signingKeyB64},
			fx.Annotated{Name: "oidc_access_token_ttl", Target: s.accessTTL},
			fx.Annotated{Name: "oidc_refresh_token_ttl", Target: s.refreshTTL},
			fx.Annotated{Name: "oidc_refresh_max_lifetime", Target: s.refreshMax},
			fx.Annotated{Name: "google_client_id", Target: testGoogleCID},
			fx.Annotated{Name: "google_auth_endpoint", Target: testGoogleAuth},
		),
	)
}

type registrarParams struct {
	fx.In
	Registrars []func(huma.API) `group:"api_registrars"`
}

func (s *FxSuite) TestProvidesRegistrarIntoGroup() {
	var got registrarParams
	app := fxtest.New(s.T(),
		s.supplyConfig(deviceUIFxClients),
		oidc.Fx(),
		fx.Populate(&got),
	)
	app.RequireStart()
	defer app.RequireStop()

	s.Require().Len(got.Registrars, 6)
}

// TestDeviceAuthorizationIsWiredIntoPublicAPI is the registration regression
// guard: graph construction must produce a POST /device_authorization route
// on the same Huma API the api package collects registrars onto. A missing
// fx provider would leave the registrar slice short; a missing fx.As binding
// on state/sqlite would fail graph construction before reaching here.
func (s *FxSuite) TestDeviceAuthorizationIsWiredIntoPublicAPI() {
	var got registrarParams
	app := fxtest.New(s.T(),
		s.supplyConfig(deviceUIFxClients),
		oidc.Fx(),
		fx.Populate(&got),
	)
	app.RequireStart()
	defer app.RequireStop()

	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("fx_test", "0.0.0"))
	for _, fn := range got.Registrars {
		fn(api)
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// A real POST hits the wired handler; an unregistered path would 404.
	// We only assert the route exists — the response body shape is the
	// concern of device_authorization_test.go.
	resp, err := http.Post(srv.URL+"/device_authorization",
		"application/x-www-form-urlencoded",
		strings.NewReader("client_id=tempogate-device"))
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.NotEqual(http.StatusNotFound, resp.StatusCode,
		"POST /device_authorization must be registered against the public huma API")
}

// TestTokenDeviceCodeBranchIsWired is the registration regression guard for
// the device-code grant on /token: graph construction must inject the
// DeviceCodeStore into tokenParams, and a POST with the RFC 8628 grant_type
// must reach the device branch (which, with an empty store, surfaces as
// invalid_grant — not unsupported_grant_type, which would mean the branch
// was never enabled).
func (s *FxSuite) TestTokenDeviceCodeBranchIsWired() {
	var got registrarParams
	app := fxtest.New(s.T(),
		s.supplyConfig(deviceUIFxClients),
		oidc.Fx(),
		fx.Populate(&got),
	)
	app.RequireStart()
	defer app.RequireStop()

	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("fx_test", "0.0.0"))
	for _, fn := range got.Registrars {
		fn(api)
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()

	body := strings.NewReader("grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=never-issued&client_id=tempogate-device")
	resp, err := http.Post(srv.URL+"/token", "application/x-www-form-urlencoded", body)
	s.Require().NoError(err)
	defer resp.Body.Close()

	// An unknown device_code reaches the device branch and returns
	// invalid_grant. unsupported_grant_type would mean the dispatch never
	// reached the new case (DeviceCodeStore not injected); 404 would mean the
	// /token registrar never ran at all.
	s.NotEqual(http.StatusNotFound, resp.StatusCode)
	s.Equal(http.StatusBadRequest, resp.StatusCode)

	var oauthErr struct {
		Error string `json:"error"`
	}
	s.Require().NoError(json.NewDecoder(resp.Body).Decode(&oauthErr))
	s.Equal("invalid_grant", oauthErr.Error,
		"device-code branch must be reachable; unsupported_grant_type means the DeviceCodeStore is not wired into tokenParams")
}

// TestInvalidTokenLifetimesFailGraph: an incoherent OIDC_*_TTL /
// OIDC_REFRESH_MAX_LIFETIME combination stops the server at startup rather
// than minting tokens whose lifecycle contradicts itself.
func (s *FxSuite) TestInvalidTokenLifetimesFailGraph() {
	s.refreshTTL = 60 * 24 * time.Hour // beyond the 30d absolute default
	var got registrarParams
	app := fx.New(
		s.supplyConfig(deviceUIFxClients),
		oidc.Fx(),
		fx.Populate(&got),
		fx.NopLogger,
	)
	s.Require().Error(app.Err())
	s.Contains(app.Err().Error(), "OIDC_REFRESH_MAX_LIFETIME")
}

func (s *FxSuite) TestMalformedClientsFailsGraph() {
	app := fx.New(
		fx.NopLogger,
		s.supplyConfig("no-colon-here"),
		oidc.Fx(),
		fx.Invoke(func(registrarParams) {}),
	)
	s.Require().Error(app.Err())
}

// TestPrefixShapedClientsFailGraph pins the C1 fail-fast: the old documented
// prefix registration must stop the graph from building instead of quietly
// turning into a URI that /authorize can never (or too often) match.
func (s *FxSuite) TestPrefixShapedClientsFailGraph() {
	app := fx.New(
		fx.NopLogger,
		s.supplyConfig("tempogate-cli:http://127.0.0.1:,"+deviceUIFxClients),
		oidc.Fx(),
		fx.Invoke(func(registrarParams) {}),
	)
	s.Require().Error(app.Err())
	s.ErrorIs(app.Err(), oidc.ErrInvalidClientRegistration)
}

// TestInsecureRedirectURIsNeedTheFlag proves OIDC_ALLOW_INSECURE_REDIRECT_URIS
// reaches the registry parser: a plain-http, non-loopback registration fails
// the graph by default and builds once the dev-only flag is set.
func (s *FxSuite) TestInsecureRedirectURIsNeedTheFlag() {
	// The device-ui callback must match the issuer (NewDeviceUI checks), so
	// only the Temporal UI registration is the insecure one under test.
	const clients = "temporal-ui:http://temporal-ui:8080/auth/sso/callback,tempogate-device-ui:" + testIssuer + "/device/sso-callback"
	secrets := "tempogate-device-ui:" + deviceUIInternalSecret

	strict := fx.New(
		fx.NopLogger,
		s.supplyConfigFull(clients, secrets, testSigningKeyB64, false),
		oidc.Fx(),
		fx.Invoke(func(registrarParams) {}),
	)
	s.Require().ErrorIs(strict.Err(), oidc.ErrInvalidClientRegistration)

	var got registrarParams
	app := fxtest.New(s.T(),
		s.supplyConfigFull(clients, secrets, testSigningKeyB64, true),
		oidc.Fx(),
		fx.Populate(&got),
	)
	app.RequireStart()
	defer app.RequireStop()
	s.NotEmpty(got.Registrars)
}

func (s *FxSuite) TestProvidesSessionManager() {
	var sm *oidc.SessionManager
	app := fxtest.New(s.T(),
		s.supplyConfig("ui:https://app.example.com/auth"),
		oidc.Fx(),
		fx.Populate(&sm),
	)
	app.RequireStart()
	defer app.RequireStop()

	s.Require().NotNil(sm)
}

// TestSessionCookieFollowsIssuer is the regression guard for the device-flow
// SSO loop: the session cookie must be scoped to the device UI under the
// issuer's base path (where the routes are actually mounted), and Secure
// only when the issuer is https, because a browser never returns a Secure
// cookie over plain http.
func (s *FxSuite) TestSessionCookieFollowsIssuer() {
	cases := []struct {
		name       string
		issuer     string
		basePath   string
		wantPath   string
		wantSecure bool
	}{
		{"https root issuer", "https://tempogate.example.com", "", "/device", true},
		{"https sub-path issuer", "https://shared.example.com/idp", "/idp", "/idp/device", true},
		{"http root issuer", "http://tempogate:8000", "", "/device", false},
		{"http sub-path issuer", "http://tempogate:8000/auth/idp", "/auth/idp", "/auth/idp/device", false},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			var sm *oidc.SessionManager
			app := fxtest.New(s.T(),
				s.supplyConfigAt(tc.issuer, tc.basePath, "ui:https://app.example.com/auth",
					"", testSigningKeyB64, false),
				oidc.Fx(),
				fx.Populate(&sm),
			)
			app.RequireStart()
			defer app.RequireStop()

			rec := httptest.NewRecorder()
			_, err := sm.Issue(s.T().Context(), rec, "alice@example.com")
			s.Require().NoError(err)
			cookies := rec.Result().Cookies()
			s.Require().Len(cookies, 1)
			s.Equal(tc.wantPath, cookies[0].Path)
			s.Equal(tc.wantSecure, cookies[0].Secure)
		})
	}
}

// TestDeviceUIIsWiredIntoPublicAPI is the registration regression guard for
// the verification-UI surface: graph construction must produce GET /device,
// POST /device, GET /device/sso-callback, GET /device/confirm,
// POST /device/approve and POST /device/deny against the same Huma API the
// api package collects registrars onto. A missing provider would short the
// registrar group; a NewDeviceUI graph-time failure would prevent
// fx.Populate from returning at all.
func (s *FxSuite) TestDeviceUIIsWiredIntoPublicAPI() {
	var got registrarParams
	app := fxtest.New(s.T(),
		s.supplyConfig(deviceUIFxClients),
		oidc.Fx(),
		fx.Populate(&got),
	)
	app.RequireStart()
	defer app.RequireStop()

	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("fx_test", "0.0.0"))
	for _, fn := range got.Registrars {
		fn(api)
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	probes := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{"GET /device", http.MethodGet, "/device", ""},
		{"POST /device", http.MethodPost, "/device", "filler=x"},
		{"GET /device/sso-callback", http.MethodGet, "/device/sso-callback?code=x&state=y", ""},
		{"GET /device/confirm", http.MethodGet, "/device/confirm?user_code=BCDF-GHJK", ""},
		{"POST /device/approve", http.MethodPost, "/device/approve", "filler=x"},
		{"POST /device/deny", http.MethodPost, "/device/deny", "filler=x"},
	}
	for _, tc := range probes {
		s.Run(tc.name, func() {
			req, err := http.NewRequest(tc.method, srv.URL+tc.path, strings.NewReader(tc.body))
			s.Require().NoError(err)
			if tc.body != "" {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.Header.Set("Origin", testIssuer)
			}
			resp, err := client.Do(req)
			s.Require().NoError(err)
			defer resp.Body.Close()
			s.NotEqualf(http.StatusNotFound, resp.StatusCode,
				"%s %s must be registered against the public huma API", tc.method, tc.path)
		})
	}
}

func (s *FxSuite) TestDeviceUIMissingInternalClientFailsGraph() {
	app := fx.New(
		fx.NopLogger,
		// Note: tempogate-device-ui is intentionally absent from the clients
		// list, mirroring the operator-misconfiguration the registrar guards
		// against. Graph construction must surface that as an actionable
		// failure rather than silently disabling the UI surface.
		s.supplyConfigFull("ui:https://app.example.com/auth,tempogate-device:", "", testSigningKeyB64, false),
		oidc.Fx(),
		fx.Invoke(func(registrarParams) {}),
	)
	s.Require().Error(app.Err())
	s.Contains(app.Err().Error(), "device-ui client", "error must point at the missing internal client")
}

func (s *FxSuite) TestDeviceUIPublicInternalClientFailsGraph() {
	app := fx.New(
		fx.NopLogger,
		// tempogate-device-ui is registered but no secret accompanies it —
		// the registrar must reject the public registration.
		s.supplyConfigFull(deviceUIFxClients, "", testSigningKeyB64, false),
		oidc.Fx(),
		fx.Invoke(func(registrarParams) {}),
	)
	s.Require().Error(app.Err())
	s.Contains(app.Err().Error(), "confidential", "error must point at the missing client secret")
}

func (s *FxSuite) TestSessionSigningKeyValidation() {
	cases := []struct {
		name string
		key  string
	}{
		{"missing key fails graph", ""},
		{"non-base64 key fails graph", "!!!not-base64!!!"},
		{"wrong length fails graph", base64.RawURLEncoding.EncodeToString([]byte("short"))},
	}

	for _, tc := range cases {
		s.Run(tc.name, func() {
			app := fx.New(
				fx.NopLogger,
				s.supplyConfigWithSessionKey("ui:https://app.example.com/auth", tc.key),
				oidc.Fx(),
				fx.Invoke(func(*oidc.SessionManager) {}),
			)
			s.Require().Error(app.Err())
		})
	}
}
