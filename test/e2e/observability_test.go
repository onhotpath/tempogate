//go:build e2e

// Acceptance proof for tempogate's operator signals against the real image:
// Prometheus counters on the admin listener after a real CLI login, refresh
// and denied login; /metrics scraped without the admin token and with a Host
// outside ADMIN_ALLOWED_HOSTS, and absent from the public listener; one
// access-log line per request with no query strings; and /readyz flipping to
// 503 once the SQLite state volume is emptied underneath the running server.
// No Temporal is needed, so the stack is mockgoogle + tempogate + cliclient.
package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
	tcnetwork "github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/onhotpath/tempogate/cli"
)

type observabilityStack struct {
	*cliStack
	tempogate testcontainers.Container
	stateVol  string
	publicURL string
	adminURL  string
}

func TestObservability(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e: skipped in -short")
	}
	t.Parallel()
	ctx := context.Background()
	st := setupObservabilityStack(ctx, t)

	// --- a real CLI login (authorization_code) ...
	(&stack{mockBaseURL: st.mockBaseURL}).setIdentity(t, allowedIdentity())
	loginDone := make(chan loginResult, 1)
	go func() {
		code, _, err := st.client.Exec(ctx,
			[]string{"tempogate", "login", insecureFlag, "--issuer", tempogateIssuer, "--client-id", cliClientID, "--token-file", cliTokenFile},
			tcexec.Multiplexed(),
		)
		loginDone <- loginResult{code: code, err: err}
	}()
	st.driveConsent(ctx, t, st.waitAuthURL(ctx, t))
	select {
	case r := <-loginDone:
		require.NoError(t, r.err)
		require.Equal(t, 0, r.code, "tempogate login must exit 0")
	case <-time.After(2 * time.Minute):
		t.Fatal("e2e: tempogate login did not complete after consent")
	}

	// --- ... then a refresh (refresh_token) ...
	tok := st.readToken(ctx, t)
	st.writeToken(ctx, t, cli.Token{AccessToken: tok.AccessToken, RefreshToken: tok.RefreshToken, ExpiresAt: time.Now().Add(-time.Minute)})
	require.NotEqual(t, tok.AccessToken, st.runToken(ctx, t), "an expired token must be refreshed")

	// --- ... and a login denied by the domain allowlist.
	(&stack{mockBaseURL: st.mockBaseURL}).setIdentity(t, mockIdentity{Sub: "google-sub-intruder-0001", Email: deniedEmail, Verified: true, HD: "evil.test"})
	require.Contains(t, st.driveDeniedLogin(ctx, t), "Access denied")

	// --- the counters on the admin listener reflect exactly that traffic. The
	// scrape carries no admin token, and its Host (the mapped host port) is
	// not in ADMIN_ALLOWED_HOSTS: /metrics needs neither.
	metrics := httpGet(t, st.adminURL+"/metrics")
	require.Equal(t, http.StatusOK, metrics.status)
	for _, want := range []string{
		`tempogate_logins_total{reason="none",result="success"} 1`,
		`tempogate_logins_total{reason="domain_not_allowed",result="failure"} 1`,
		`tempogate_tokens_issued_total{grant="authorization_code"} 1`,
		`tempogate_tokens_issued_total{grant="refresh_token"} 1`,
		`tempogate_upstream_request_duration_seconds_count{op="code_exchange"} 2`,
		`tempogate_upstream_request_duration_seconds_count{op="discovery"} 1`,
		`tempogate_build_info{`,
		`go_goroutines `,
	} {
		require.Contains(t, metrics.body, want)
	}
	require.NotContains(t, metrics.body, allowedEmail, "no identity may become a label")
	require.NotContains(t, metrics.body, deniedEmail, "no identity may become a label")

	// --- /metrics is an admin-only surface.
	require.Equal(t, http.StatusNotFound, httpGet(t, st.publicURL+"/metrics").status)

	// --- one access-log line per request, never with its query string.
	// Scrapes log at debug, so hit a regular admin route for an info line.
	httpGet(t, st.adminURL+"/admin/keys")
	logs := st.logs(ctx, t)
	var requestLines []string
	for _, line := range strings.Split(logs, "\n") {
		if strings.Contains(line, "http request") {
			requestLines = append(requestLines, line)
		}
	}
	for _, path := range []string{`"path": "/authorize"`, `"path": "/callback/google"`, `"path": "/token"`} {
		require.Truef(t, containsAny(requestLines, path), "no access-log line with %s in:\n%s", path, logs)
	}
	require.Truef(t, containsAny(requestLines, `"listener": "admin"`), "admin requests are logged too:\n%s", logs)
	for _, line := range requestLines {
		for _, leak := range []string{"?", "code=", "state=", "code_challenge", "refresh_token=", "Bearer"} {
			require.NotContainsf(t, line, leak, "access log leaked %q", leak)
		}
	}

	// --- /readyz tracks the state store; /healthz (liveness) does not.
	require.Equal(t, http.StatusOK, httpGet(t, st.publicURL+"/readyz").status)
	st.emptyStateVolume(ctx, t)
	require.Eventually(t, func() bool {
		return httpGet(t, st.publicURL+"/readyz").status == http.StatusServiceUnavailable
	}, 30*time.Second, 500*time.Millisecond, "/readyz must report 503 once the database file is gone")
	require.Equal(t, http.StatusOK, httpGet(t, st.publicURL+"/healthz").status)
	require.Contains(t, httpGet(t, st.adminURL+"/metrics").body, `tempogate_db_errors_total{op="probe"}`)
}

// driveDeniedLogin starts a fresh authorization request as the CLI client and
// lets the browser follow it through the mock consent to tempogate's 403
// page. The loopback redirect is never reached, so no CLI process is needed.
func (s *observabilityStack) driveDeniedLogin(ctx context.Context, t *testing.T) string {
	t.Helper()
	sum := sha256.Sum256([]byte("observability-e2e-verifier-0123456789abcdefghijk"))
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {cliClientID},
		"redirect_uri":          {"http://127.0.0.1:1/callback"},
		"scope":                 {"openid email"},
		"state":                 {"denied-login"},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	allocCtx, cancelAlloc := chromedp.NewRemoteAllocator(ctx, s.chromeWS)
	t.Cleanup(cancelAlloc)
	bctx, cancelBrowser := chromedp.NewContext(allocCtx)
	t.Cleanup(cancelBrowser)

	var body string
	err := chromedp.Run(bctx,
		chromedp.Navigate(tempogateIssuer+"/authorize?"+q.Encode()),
		chromedp.WaitVisible(`#approve`, chromedp.ByID),
		chromedp.Click(`#approve`, chromedp.ByID),
		chromedp.WaitVisible(`h1`, chromedp.ByQuery),
		chromedp.Text(`body`, &body, chromedp.ByQuery),
	)
	require.NoError(t, err, "denied login browser flow")
	return body
}

// emptyStateVolume deletes the database, WAL and shared-memory files from
// the state volume while tempogate keeps running. The distroless tempogate
// image has no shell, so a throwaway container from the cliclient image
// (Debian) does it through the shared volume.
func (s *observabilityStack) emptyStateVolume(ctx context.Context, t *testing.T) {
	t.Helper()
	img, from := builtImageSource("E2E_CLICLIENT_IMAGE", "test/e2e/cliclient/Dockerfile", repoRoot(t))
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:          img,
			FromDockerfile: from,
			Entrypoint:     []string{"sh", "-c", "rm -f /state/state.db /state/state.db-wal /state/state.db-shm"},
			User:           "0:0",
			Mounts:         testcontainers.Mounts(testcontainers.VolumeMount(s.stateVol, "/state")),
			WaitingFor:     wait.ForExit().WithExitTimeout(time.Minute),
		},
		Started: true,
	})
	require.NoError(t, err, "state wiper")
	track(ctx, t, "state-wiper", c)
	state, err := c.State(ctx)
	require.NoError(t, err)
	require.Equal(t, 0, state.ExitCode, "state wiper failed")
}

func (s *observabilityStack) logs(ctx context.Context, t *testing.T) string {
	t.Helper()
	rc, err := s.tempogate.Logs(ctx)
	require.NoError(t, err)
	defer func() { _ = rc.Close() }()
	b, err := io.ReadAll(rc)
	require.NoError(t, err)
	return string(b)
}

type httpResult struct {
	status int
	body   string
}

func httpGet(t *testing.T, u string) httpResult {
	t.Helper()
	resp, err := http.Get(u)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return httpResult{status: resp.StatusCode, body: string(b)}
}

func containsAny(lines []string, sub string) bool {
	for _, l := range lines {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}

func setupObservabilityStack(ctx context.Context, t *testing.T) *observabilityStack {
	t.Helper()
	root := repoRoot(t)

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
		"HTTP_LISTENER": "0.0.0.0:8000",
		// Test-only: the admin listener (and with it /metrics) defaults to
		// loopback, which the host cannot reach through the port mapping.
		"ADMIN_LISTENER":              "0.0.0.0:8081",
		"STATE_SQLITE_PATH":           "/state/state.db",
		"OIDC_ISSUER":                 tempogateIssuer,
		"OIDC_CLIENTS":                cliClientID + ":http://127.0.0.1/callback",
		"OIDC_ALLOWED_DOMAINS":        "example.com",
		"OIDC_ALLOWED_HOSTED_DOMAINS": hostedDomain,
		"OIDC_GOOGLE_CLIENT_ID":       "tempogate-upstream",
		"OIDC_GOOGLE_CLIENT_SECRET":   "tempogate-upstream-secret",
		"OIDC_GOOGLE_AUTH_ENDPOINT":   mockIssuer + "/auth",
		"OIDC_GOOGLE_TOKEN_ENDPOINT":  mockIssuer + "/token",
		"OIDC_GOOGLE_ISSUER_URL":      mockIssuer,
	}
	addDeviceUIServerEnv(env, tempogateIssuer)
	stateVol := fmt.Sprintf("tempogate-observability-e2e-state-%d", time.Now().UnixNano())
	t.Cleanup(func() { removeVolume(ctx, t, stateVol) })
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
			Networks:       []string{nw.Name},
			NetworkAliases: alias("tempogate"),
			WaitingFor:     wait.ForHTTP("/readyz").WithPort("8000/tcp").WithStartupTimeout(2 * time.Minute),
		},
		Started: true,
	})
	require.NoError(t, err, "tempogate serve")
	track(ctx, t, "tempogate", tempogate)

	cliImg, cliFrom := builtImageSource("E2E_CLICLIENT_IMAGE", "test/e2e/cliclient/Dockerfile", root)
	clientC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:          cliImg,
			FromDockerfile: cliFrom,
			ExposedPorts:   []string{"9222/tcp"},
			Networks:       []string{nw.Name},
			NetworkAliases: alias("cliclient"),
			WaitingFor:     wait.ForHTTP("/json/version").WithPort("9222/tcp").WithStartupTimeout(2 * time.Minute),
		},
		Started: true,
	})
	require.NoError(t, err, "cliclient")
	track(ctx, t, "cliclient", clientC)

	return &observabilityStack{
		cliStack: &cliStack{
			mockBaseURL: mappedHTTP(ctx, t, mock, "8080"),
			client:      clientC,
			chromeWS:    devtoolsWS(ctx, t, clientC),
		},
		tempogate: tempogate,
		stateVol:  stateVol,
		publicURL: mappedHTTP(ctx, t, tempogate, "8000"),
		adminURL:  mappedHTTP(ctx, t, tempogate, "8081"),
	}
}
