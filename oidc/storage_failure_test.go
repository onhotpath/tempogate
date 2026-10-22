package oidc_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/onhotpath/tempogate/api"
	"github.com/onhotpath/tempogate/api/requestid"
	"github.com/onhotpath/tempogate/keys"
	"github.com/onhotpath/tempogate/oidc"
	"github.com/onhotpath/tempogate/state/sqlite"
)

// TestStorageFailureIsSanitized drives the real OIDC handlers over the real
// sqlite store with its tables dropped underneath, the same shape as a
// corrupted or half-migrated state DB in production. Anonymous callers must
// get a generic 5xx that names a request id, never the SQLite text or the DB
// path; the operator gets the detail in a log line keyed by that id. The
// device UI is a browser surface, so its 5xx is an HTML page, not JSON.
func TestStorageFailureIsSanitized(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "state.db")

	store, err := sqlite.New(sqlite.WithPath(dbPath))
	require.NoError(t, err)
	require.NoError(t, store.Migrate(ctx))
	t.Cleanup(func() { _ = store.Close() })

	k := keys.New(keys.WithStore(store), keys.WithGenerateOptions(keys.WithRSABits(2048)))
	require.NoError(t, k.Init(ctx))
	signer := keys.NewSigner(keys.WithKeys(k), keys.WithIssuer(testIssuer))

	reg, err := oidc.ParseClientRegistry("ui:" + testRedirectURI + ",tempogate-device:,tempogate-device-ui:" + testIssuer + "/device/sso-callback")
	require.NoError(t, err)
	require.NoError(t, reg.WithSecrets("tempogate-device-ui:"+deviceUIInternalSecret))

	signKey := []byte("0123456789abcdef0123456789abcdef")
	authorizer := oidc.New(store, reg, newTestBinding(t, testIssuer), testIssuer, testGoogleCID, "https://accounts.example.com/auth")
	token := oidc.NewToken(store, signer, reg, oidc.WithPermissionResolver(permitAll), oidc.WithDeviceCodeStore(store))
	device := oidc.NewDeviceAuthorization(store, reg, testIssuer)
	var uiLogs bytes.Buffer
	deviceUI, err := oidc.NewDeviceUI(store, oidc.NewSessionManager(store, signKey), reg, token, signKey, testIssuer, oidc.WithDeviceUIPermissionResolver(permitAll),
		oidc.WithDeviceUILogger(slog.New(slog.NewJSONHandler(&uiLogs, nil))),
	)
	require.NoError(t, err)

	core, apiLogs := observer.New(zapcore.DebugLevel)
	servers := api.New(api.NewReadiness(),
		api.WithLogger(zap.New(core)),
		api.WithRegistrar(authorizer.Register),
		api.WithRegistrar(token.Register),
		api.WithRegistrar(device.Register),
		api.WithRegistrar(deviceUI.Register),
	)
	srv := httptest.NewServer(servers.Public.Handler)
	t.Cleanup(srv.Close)

	raw, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	_, err = raw.ExecContext(ctx, `DROP TABLE auth_requests; DROP TABLE auth_codes; DROP TABLE refresh_tokens; DROP TABLE device_codes;`)
	require.NoError(t, err)
	require.NoError(t, raw.Close())

	const (
		authCode     = "auth-code-secret-value"
		refreshToken = "refresh-token-secret-value"
	)
	authorizeQ := url.Values{
		"response_type": {"code"}, "client_id": {"ui"}, "redirect_uri": {testRedirectURI},
		"scope": {"openid email"}, "state": {"s"},
		"code_challenge": {pkceChallenge}, "code_challenge_method": {"S256"},
	}
	form := func(v url.Values) (string, io.Reader) {
		return "application/x-www-form-urlencoded", strings.NewReader(v.Encode())
	}
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	jsonCases := []struct {
		name string
		do   func() (*http.Response, error)
	}{
		{"authorize", func() (*http.Response, error) { return noRedirect.Get(srv.URL + "/authorize?" + authorizeQ.Encode()) }},
		{"token authorization_code", func() (*http.Response, error) {
			ct, body := form(url.Values{
				"grant_type": {"authorization_code"}, "code": {authCode}, "client_id": {"ui"},
				"redirect_uri": {testRedirectURI}, "code_verifier": {pkceVerifier},
			})
			return noRedirect.Post(srv.URL+"/token", ct, body)
		}},
		{"token refresh_token", func() (*http.Response, error) {
			ct, body := form(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}, "client_id": {"ui"}})
			return noRedirect.Post(srv.URL+"/token", ct, body)
		}},
		{"device_authorization", func() (*http.Response, error) {
			ct, body := form(url.Values{"client_id": {"tempogate-device"}, "scope": {"openid email"}})
			return noRedirect.Post(srv.URL+oidc.DeviceAuthorizationPath, ct, body)
		}},
	}
	for _, tc := range jsonCases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := tc.do()
			require.NoError(t, err)
			body := readBody(t, resp)
			_ = resp.Body.Close()
			reqID := resp.Header.Get(requestid.Header)

			require.Equalf(t, http.StatusInternalServerError, resp.StatusCode, "body: %s", body)
			assertNoInternals(t, body, dbPath)
			var p struct {
				Detail string `json:"detail"`
			}
			require.NoError(t, json.Unmarshal([]byte(body), &p))
			require.NotEmpty(t, reqID)
			assert.Contains(t, p.Detail, reqID)

			entries := apiLogs.FilterField(zap.String("request_id", reqID)).All()
			require.Len(t, entries, 1)
			assert.Contains(t, entries[0].ContextMap()["error"], "no such table")
		})
	}

	t.Run("device ui renders an HTML 500", func(t *testing.T) {
		ct, body := form(url.Values{"user_code": {deviceUITestUserDisplay}})
		resp, err := noRedirect.Post(srv.URL+"/device", ct, body)
		require.NoError(t, err)
		page := readBody(t, resp)
		_ = resp.Body.Close()
		reqID := resp.Header.Get(requestid.Header)

		require.Equal(t, http.StatusInternalServerError, resp.StatusCode)
		assert.True(t, strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html"), "got %q", resp.Header.Get("Content-Type"))
		assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
		assertNoInternals(t, page, dbPath)
		require.NotEmpty(t, reqID)
		assert.Contains(t, page, reqID)
		assert.Contains(t, uiLogs.String(), reqID)
		assert.Contains(t, uiLogs.String(), "no such table")
	})

	for _, secret := range []string{authCode, refreshToken} {
		for _, e := range apiLogs.All() {
			assert.NotContains(t, e.ContextMap()["error"], secret)
		}
		assert.NotContains(t, uiLogs.String(), secret)
	}
}

func assertNoInternals(t *testing.T, body, dbPath string) {
	t.Helper()
	for _, s := range []string{"sqlite", "SQL logic error", "no such table", dbPath, filepath.Dir(dbPath)} {
		assert.NotContainsf(t, body, s, "response leaks internal detail %q:\n%s", s, body)
	}
}
