//go:build e2e

// Acceptance proof for the anti-framing and security headers against the real
// image: both listeners send them, the device approval UI cannot be framed by
// a page on another origin (checked in headless Chrome, which is what
// actually enforces frame-ancestors / X-Frame-Options), the API docs are off
// by default, and the public /healthz no longer reveals the build version.
package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"testing"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcnetwork "github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/onhotpath/tempogate/oidc"
)

func TestSecurityHeaders(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e: skipped in -short")
	}
	t.Parallel()
	ctx := context.Background()
	root := repoRoot(t)

	net, err := tcnetwork.New(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = net.Remove(ctx) })
	alias := func(name string) map[string][]string { return map[string][]string{net.Name: {name}} }

	env := map[string]string{
		"HTTP_LISTENER":              "0.0.0.0:8000",
		"ADMIN_LISTENER":             "0.0.0.0:8081",
		"STATE_SQLITE_PATH":          "/state/state.db",
		"OIDC_ISSUER":                tempogateIssuer,
		"OIDC_ALLOW_INSECURE_ISSUER": "true", // plain-http issuer on the test network
		"OIDC_CLIENTS":               deviceClientID + ":",
		"OIDC_ALLOWED_DOMAINS":       "example.com",
		"OIDC_GOOGLE_CLIENT_ID":      "tempogate-upstream",
		"OIDC_GOOGLE_CLIENT_SECRET":  "tempogate-upstream-secret",
		"OIDC_GOOGLE_AUTH_ENDPOINT":  mockIssuer + "/auth",
		"OIDC_GOOGLE_TOKEN_ENDPOINT": mockIssuer + "/token",
		"OIDC_GOOGLE_ISSUER_URL":     mockIssuer,
	}
	addDeviceUIServerEnv(env, tempogateIssuer)

	// Registered before the containers so it runs after they are terminated
	// (t.Cleanup is LIFO): a volume in use cannot be removed.
	stateVol := fmt.Sprintf("tempogate-headers-e2e-state-%d", time.Now().UnixNano())
	t.Cleanup(func() { _ = exec.Command("docker", "volume", "rm", "-f", stateVol).Run() })
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
			ExposedPorts:   []string{"8000/tcp", "8081/tcp"},
			Networks:       []string{net.Name},
			NetworkAliases: alias("tempogate"),
			WaitingFor: wait.ForAll(
				wait.ForHTTP("/readyz").WithPort("8000/tcp"),
				wait.ForHTTP("/admin/healthz").WithPort("8081/tcp"),
			).WithDeadline(2 * time.Minute),
		},
		Started: true,
	})
	require.NoError(t, err, "tempogate serve")
	track(ctx, t, "tempogate", tempogate)

	public := mappedHTTP(ctx, t, tempogate, "8000")
	admin := mappedHTTP(ctx, t, tempogate, "8081")
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	get := func(t *testing.T, u string) (*http.Response, []byte) {
		t.Helper()
		resp, err := noRedirect.Get(u)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		b, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		return resp, b
	}

	t.Run("headers on both listeners", func(t *testing.T) {
		for _, u := range []string{
			public + oidc.DevicePath,
			public + oidc.DeviceConfirmPath + "?user_code=BCDF-GHJK",
			public + "/.well-known/openid-configuration",
			public + "/healthz",
			public + "/no-such-route",
			admin + "/admin/healthz",
			admin + "/no-such-route",
		} {
			resp, _ := get(t, u)
			assert.Equal(t, "DENY", resp.Header.Get("X-Frame-Options"), u)
			assert.Equal(t, "nosniff", resp.Header.Get("X-Content-Type-Options"), u)
			assert.NotEmpty(t, resp.Header.Get("Referrer-Policy"), u)
			assert.Contains(t, resp.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'", u)
		}
	})

	t.Run("api docs off by default", func(t *testing.T) {
		for _, base := range []string{public, admin} {
			for _, p := range []string{"/openapi.json", "/openapi.yaml", "/docs", "/schemas/HealthBody.json"} {
				resp, _ := get(t, base+p)
				assert.Equal(t, http.StatusNotFound, resp.StatusCode, base+p)
			}
		}
	})

	t.Run("public healthz omits the version", func(t *testing.T) {
		_, body := get(t, public+"/healthz")
		var h map[string]any
		require.NoError(t, json.Unmarshal(body, &h))
		assert.Equal(t, "ok", h["status"])
		assert.NotContains(t, h, "version")

		_, body = get(t, admin+"/admin/healthz")
		h = map[string]any{}
		require.NoError(t, json.Unmarshal(body, &h))
		assert.NotEmpty(t, h["version"], "the private admin probe keeps the version")
	})

	t.Run("device UI cannot be framed by another origin", func(t *testing.T) {
		chrome, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Image: chromeImage,
				Cmd: []string{
					"--remote-debugging-address=0.0.0.0", "--remote-debugging-port=9222",
					"--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage",
				},
				ExposedPorts: []string{"9222/tcp"},
				Networks:     []string{net.Name},
				WaitingFor:   wait.ForHTTP("/json/version").WithPort("9222/tcp").WithStartupTimeout(2 * time.Minute),
			},
			Started: true,
		})
		require.NoError(t, err, "chrome")
		track(ctx, t, "chrome", chrome)

		allocCtx, cancelAlloc := chromedp.NewRemoteAllocator(ctx, devtoolsWS(ctx, t, chrome))
		defer cancelAlloc()
		browserCtx, cancelBrowser := chromedp.NewContext(allocCtx)
		defer cancelBrowser()
		browserCtx, cancelTimeout := context.WithTimeout(browserCtx, 90*time.Second)
		defer cancelTimeout()

		for _, target := range []string{
			tempogateIssuer + oidc.DeviceConfirmPath + "?user_code=BCDF-GHJK",
			tempogateIssuer + oidc.DevicePath + "?user_code=BCDF-GHJK",
		} {
			// The attacker page lives on an opaque data: origin. The srcdoc
			// frame is the control: it must render, so a blocked target
			// frame is the policy at work and not a harness that renders
			// nothing.
			attacker := "data:text/html," + url.PathEscape(
				`<iframe name="control" srcdoc="<p>control</p>"></iframe>`+
					`<iframe name="victim" src="`+target+`"></iframe>`)
			frames := framesAfterLoad(t, browserCtx, attacker)

			control, ok := frames["control"]
			require.True(t, ok, "control frame missing")
			assert.Equal(t, "about:srcdoc", control.URL, "control frame must render")

			victim, ok := frames["victim"]
			require.True(t, ok, "victim frame missing")
			assert.Equal(t, "chrome-error://chromewebdata/", victim.URL,
				"%s rendered inside a cross-origin frame (now at %s): it must be blocked", target, victim.URL)
		}

		// Loaded top-level, the page must still be styled: the CSP allows
		// its inline stylesheet by hash only, so a hash that drifted from
		// the CSS would leave the button with the browser's default style.
		var background string
		require.NoError(t, chromedp.Run(browserCtx,
			chromedp.Navigate(tempogateIssuer+oidc.DevicePath),
			chromedp.WaitVisible(`#user_code`, chromedp.ByID),
			chromedp.Evaluate(`getComputedStyle(document.querySelector("button.primary")).backgroundColor`, &background),
		))
		assert.Equal(t, "rgb(31, 111, 235)", background, "the device page's inline stylesheet must apply under its CSP")
	})
}

// framesAfterLoad navigates to pageURL and returns its child frames by name
// once every one has committed a document other than the initial about:blank.
func framesAfterLoad(t *testing.T, ctx context.Context, pageURL string) map[string]*cdp.Frame {
	t.Helper()
	require.NoError(t, chromedp.Run(ctx, chromedp.Navigate(pageURL)))
	var frames map[string]*cdp.Frame
	require.Eventually(t, func() bool {
		var tree *page.FrameTree
		if err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
			var err error
			tree, err = page.GetFrameTree().Do(ctx)
			return err
		})); err != nil {
			return false
		}
		frames = map[string]*cdp.Frame{}
		for _, child := range tree.ChildFrames {
			if child.Frame.URL == "" || child.Frame.URL == "about:blank" {
				return false
			}
			frames[child.Frame.Name] = child.Frame
		}
		return len(frames) == 2
	}, 30*time.Second, 250*time.Millisecond, "child frames never committed")
	return frames
}
