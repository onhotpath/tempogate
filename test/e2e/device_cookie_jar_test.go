//go:build e2e

// Acceptance proof that the device-flow verification UI works with real
// browser cookie semantics. The driver below is a net/http client with a
// cookiejar that addresses tempogate and mock Google by their Docker-network
// URLs (http://tempogate:8000, http://mockgoogle:8080), exactly as a browser
// on that network would, and only rewrites the TCP dial to the host-mapped
// ports. The jar therefore applies the Path and Secure attributes the server
// actually sets: a cookie scoped to the wrong path, or marked Secure on a
// plain-http issuer, is never sent back and the flow loops back to the
// upstream IdP instead of reaching /device/confirm.
package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcnetwork "github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/onhotpath/tempogate/oidc"
)

// TestDeviceLoginCookieJar runs the RFC 8628 device flow end to end (device
// authorization, verification UI, token poll) at a root issuer and at a
// sub-path issuer, with the verification UI driven through a real cookie jar.
func TestDeviceLoginCookieJar(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e: skipped in -short")
	}
	t.Parallel()
	for _, basePath := range []string{"", "/idp"} {
		t.Run("issuer path "+fmt.Sprintf("%q", basePath), func(t *testing.T) {
			ctx := context.Background()
			issuer, browser := setupDeviceStack(ctx, t, basePath)

			resp, err := browser.PostForm(issuer+oidc.DeviceAuthorizationPath,
				url.Values{"client_id": {deviceClientID}, "scope": {"openid email"}})
			require.NoError(t, err)
			var da struct {
				DeviceCode string `json:"device_code"`
				UserCode   string `json:"user_code"`
			}
			require.Equal(t, http.StatusOK, resp.StatusCode)
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&da))
			_ = resp.Body.Close()

			driveVerificationUI(ctx, t, browser, issuer, da.UserCode, "approve")

			resp, err = browser.PostForm(issuer+oidc.TokenPath, url.Values{
				"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
				"device_code": {da.DeviceCode},
				"client_id":   {deviceClientID},
			})
			require.NoError(t, err)
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			require.Equalf(t, http.StatusOK, resp.StatusCode, "device_code grant after approve: %s", body)
			var tok struct {
				AccessToken string `json:"access_token"`
			}
			require.NoError(t, json.Unmarshal(body, &tok))
			require.Regexp(t, jwtPattern, tok.AccessToken)
		})
	}
}

// setupDeviceStack brings up mock Google and tempogate (issuer
// tempogateIssuer+basePath) on a private network and returns the issuer plus
// a browser client for it. No Temporal or headless Chrome: the device flow's
// browser leg is the only thing under test.
func setupDeviceStack(ctx context.Context, t *testing.T, basePath string) (string, *http.Client) {
	t.Helper()
	root := repoRoot(t)
	issuer := tempogateIssuer + basePath

	nw, err := tcnetwork.New(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = nw.Remove(ctx) })
	alias := func(name string) map[string][]string { return map[string][]string{nw.Name: {name}} }

	mockImg, mockFrom := builtImageSource("E2E_MOCKGOOGLE_IMAGE", "test/e2e/mockgoogle/Dockerfile", root)
	mock, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:          mockImg,
			FromDockerfile: mockFrom,
			Env:            map[string]string{"MOCK_ISSUER": mockIssuer},
			ExposedPorts:   []string{"8080/tcp"},
			Networks:       []string{nw.Name},
			NetworkAliases: alias("mockgoogle"),
			WaitingFor:     wait.ForHTTP("/healthz").WithPort("8080/tcp").WithStartupTimeout(2 * time.Minute),
		},
		Started: true,
	})
	require.NoError(t, err, "mockgoogle")
	track(ctx, t, "mockgoogle", mock)

	env := map[string]string{
		"HTTP_LISTENER":              "0.0.0.0:8000",
		"STATE_SQLITE_PATH":          "/state/state.db",
		"OIDC_ISSUER":                issuer,
		"OIDC_ALLOW_INSECURE_ISSUER": "true", // plain-http issuer on the test network
		"OIDC_CLIENTS":               deviceClientID + ":",
		"OIDC_ALLOWED_DOMAINS":       "example.com",
		"OIDC_GOOGLE_CLIENT_ID":      "tempogate-upstream",
		"OIDC_GOOGLE_CLIENT_SECRET":  "tempogate-upstream-secret",
		"OIDC_GOOGLE_AUTH_ENDPOINT":  mockIssuer + "/auth",
		"OIDC_GOOGLE_TOKEN_ENDPOINT": mockIssuer + "/token",
		"OIDC_GOOGLE_ISSUER_URL":     mockIssuer,
	}
	addDeviceUIServerEnv(env, issuer)
	stateVol := stateVolume(t, "tempogate-device-jar-e2e-state")
	tgImg, tgFrom := builtImageSource("E2E_TEMPOGATE_IMAGE", "Dockerfile", root)

	migrate, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:          tgImg,
			FromDockerfile: tgFrom,
			Cmd:            []string{"migrate"},
			Env:            env,
			User:           "0:0",
			Mounts:         testcontainers.Mounts(testcontainers.VolumeMount(stateVol, "/state")),
			WaitingFor:     wait.ForExit().WithExitTimeout(2 * time.Minute),
		},
		Started: true,
	})
	require.NoError(t, err, "tempogate migrate")
	track(ctx, t, "tempogate-migrate", migrate)

	tempogate, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:          tgImg,
			FromDockerfile: tgFrom,
			Cmd:            []string{"serve"},
			Env:            env,
			User:           "0:0",
			Mounts:         testcontainers.Mounts(testcontainers.VolumeMount(stateVol, "/state")),
			ExposedPorts:   []string{"8000/tcp"},
			Networks:       []string{nw.Name},
			NetworkAliases: alias("tempogate"),
			WaitingFor:     wait.ForHTTP("/readyz").WithPort("8000/tcp").WithStartupTimeout(2 * time.Minute),
		},
		Started: true,
	})
	require.NoError(t, err, "tempogate serve")
	track(ctx, t, "tempogate", tempogate)

	return issuer, newBrowserClient(t, map[string]string{
		"tempogate:8000":  mappedAddr(ctx, t, tempogate, "8000"),
		"mockgoogle:8080": mappedAddr(ctx, t, mock, "8080"),
	})
}

// newBrowserClient returns an HTTP client that behaves like a browser on the
// Docker network: it follows redirects and keeps cookies in a jar keyed by
// the network host names, while dialing each host through its host-mapped
// address (dialMap: "host:port" on the network -> reachable "host:port").
func newBrowserClient(t *testing.T, dialMap map[string]string) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if mapped, ok := dialMap[addr]; ok {
			addr = mapped
		}
		return dialer.DialContext(ctx, network, addr)
	}
	return &http.Client{
		Jar:       jar,
		Transport: transport,
		Timeout:   15 * time.Second,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 15 {
				return fmt.Errorf("e2e: redirect budget exceeded after %d hops", len(via))
			}
			return nil
		},
	}
}

// driveVerificationUI walks the RFC 8628 verification UI as a browser would:
// submit the user_code, approve at the mock upstream consent page, land on
// /device/confirm (only reachable if the session cookie set by
// /device/sso-callback comes back), then POST the decision with the CSRF
// token. browser must be a newBrowserClient; issuer is the network-side
// issuer URL.
func driveVerificationUI(ctx context.Context, t *testing.T, browser *http.Client, issuer, userCode, decision string) {
	t.Helper()
	csrf := openConfirmPage(t, browser, issuer, userCode)
	req := decisionRequest(ctx, t, issuer, userCode, decision, csrf)
	// net/http never sends Origin; a browser does on a form POST, and
	// tempogate's CSRF defence requires it to match the issuer origin.
	issuerURL := mustParseURL(t, issuer)
	req.Header.Set("Origin", issuerURL.Scheme+"://"+issuerURL.Host)
	resp, err := browser.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equalf(t, http.StatusOK, resp.StatusCode, "%s: %s", resp.Request.URL, body)
}

// openConfirmPage submits userCode on the verification page, approves at the
// mock upstream consent page (unless the browser already has a session) and
// returns the CSRF token of the
// /device/confirm page the browser lands on.
func openConfirmPage(t *testing.T, browser *http.Client, issuer, userCode string) string {
	t.Helper()
	page := func(resp *http.Response, err error) (string, string) {
		t.Helper()
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equalf(t, http.StatusOK, resp.StatusCode, "%s: %s", resp.Request.URL, body)
		return resp.Request.URL.String(), string(body)
	}

	at, body := page(browser.PostForm(issuer+oidc.DevicePath, url.Values{"user_code": {userCode}}))
	if csrf := csrfTokenPattern.FindStringSubmatch(body); csrf != nil {
		// A browser that already holds a session skips the upstream bounce.
		return csrf[1]
	}
	href := mockApproveHrefPattern.FindStringSubmatch(body)
	require.NotEmptyf(t, href, "POST /device must land on the upstream consent page, got %s:\n%s", at, body)

	at, body = page(browser.Get(mockIssuer + href[1]))
	csrf := csrfTokenPattern.FindStringSubmatch(body)
	require.NotEmptyf(t, csrf,
		"after upstream consent the browser must reach %s%s; it landed on %s instead, which means the %s cookie set by %s%s was not sent back (cookies the jar would send to the confirm page: %v)",
		issuer, oidc.DeviceConfirmPath, at, oidc.DefaultSessionCookieName, issuer, oidc.DeviceSSOCallbackPath,
		browser.Jar.Cookies(mustParseURL(t, issuer+oidc.DeviceConfirmPath)))
	return csrf[1]
}

// decisionRequest builds the approve/deny form POST the confirm page
// submits, without Origin or Referer; callers set whichever they test.
func decisionRequest(ctx context.Context, t *testing.T, issuer, userCode, decision, csrf string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, issuer+oidc.DevicePath+"/"+decision,
		strings.NewReader(url.Values{"csrf_token": {csrf}, "user_code": {userCode}}.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	require.NoError(t, err)
	return u
}
