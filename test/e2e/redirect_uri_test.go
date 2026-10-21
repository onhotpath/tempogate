//go:build e2e

// Acceptance proof for exact redirect_uri matching (C1): the real tempogate
// image, federating to the real mock Google over a Docker network, must
// never hand an authorization code to a host the client did not register.
//
// Each vector is driven through the whole browser chain from the test
// process (tempogate /authorize, mock Google consent, tempogate
// /callback/google) rather than stopping at the first response, so the
// assertion is the one that matters to an attacker: which URL the final 302
// sends the victim's browser (and code) to. The loopback positive case
// proves an ephemeral CLI port is still accepted with the exact registered
// path.
//
// The legacy subtest boots tempogate with the pre-C1 documented prefix
// registration (`tempogate-cli:http://127.0.0.1:`) and requires the server
// to refuse it at startup. Should it boot anyway, the subtest runs the
// userinfo attack against it so a regression fails with the concrete
// consequence (where the code went) instead of a bare boot assertion.
package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcnetwork "github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	redirectUIClientID = "ui"
	redirectUICallback = "https://ui.example.com/auth/sso/callback"

	// attackerVerifier is the PKCE verifier the attacker generates for
	// themselves; PKCE gives no protection when the attacker owns the
	// challenge, which is exactly why redirect_uri matching must hold.
	attackerVerifier = "attacker-controlled-verifier-0123456789abcdefghijklmnopqrstuvwxyz"
)

func TestRedirectURIExactMatching(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e: skipped in -short")
	}
	t.Parallel()
	ctx := context.Background()
	root := repoRoot(t)

	net, err := tcnetwork.New(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = net.Remove(ctx) })
	netName := net.Name

	mockImg, mockFrom := builtImageSource("E2E_MOCKGOOGLE_IMAGE", "test/e2e/mockgoogle/Dockerfile", root)
	mock, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:          mockImg,
			FromDockerfile: mockFrom,
			Env:            map[string]string{"MOCK_ISSUER": mockIssuer},
			ExposedPorts:   []string{"8080/tcp"},
			Networks:       []string{netName},
			NetworkAliases: map[string][]string{netName: {"mockgoogle"}},
			WaitingFor:     wait.ForHTTP("/healthz").WithPort("8080/tcp").WithStartupTimeout(2 * time.Minute),
		},
		Started: true,
	})
	require.NoError(t, err, "mockgoogle")
	track(ctx, t, "mockgoogle", mock)
	mockBase := mappedHTTP(ctx, t, mock, "8080")

	t.Run("legacy prefix registration refuses to boot", func(t *testing.T) {
		env := redirectTestEnv(cliClientID + ":http://127.0.0.1:")
		tg := startTempogateAllowingFailure(ctx, t, root, netName, "tempogate-legacy", env)
		if tg.booted {
			status, delivered := driveCodeFlow(t, tg.base, mockBase, cliClientID, "http://127.0.0.1:@evil.example/callback")
			t.Fatalf("tempogate booted with the prefix registration %q; /authorize answered %d and the "+
				"victim's code was delivered to %q", env["OIDC_CLIENTS"], status, delivered)
		}
		require.Contains(t, tg.logs, cliClientID,
			"the startup error must name the offending client entry")
	})

	t.Run("attacker redirect_uri vectors never receive a code", func(t *testing.T) {
		env := redirectTestEnv(
			cliClientID + ":http://127.0.0.1/callback," +
				redirectUIClientID + ":" + redirectUICallback,
		)
		tg := startTempogateAllowingFailure(ctx, t, root, netName, "tempogate-exact", env)
		require.Truef(t, tg.booted, "tempogate must boot with exact registrations; logs:\n%s", tg.logs)

		vectors := []struct {
			name, clientID, redirectURI string
		}{
			{"loopback userinfo hides attacker host", cliClientID, "http://127.0.0.1:@evil.example/callback"},
			{"loopback userinfo with port", cliClientID, "http://127.0.0.1:1234@evil.example/callback"},
			{"loopback host suffix", cliClientID, "http://127.0.0.1.evil.example:1234/callback"},
			{"localhost is not the registered loopback", cliClientID, "http://localhost:1234/callback"},
			{"loopback fragment", cliClientID, "http://127.0.0.1:1234/callback#frag"},
			{"loopback unexpected query", cliClientID, "http://127.0.0.1:1234/callback?next=https://evil.example"},
			{"host suffix", redirectUIClientID, "https://ui.example.com.evil.example/auth/sso/callback"},
			{"userinfo hides attacker host", redirectUIClientID, "https://ui.example.com@evil.example/auth/sso/callback"},
			{"dot-segment escape to an open redirect", redirectUIClientID, redirectUICallback + "/../../open-redirect?to=https://evil.example"},
			{"path extension", redirectUIClientID, redirectUICallback + "/extra"},
			{"uppercase host", redirectUIClientID, "https://UI.example.com/auth/sso/callback"},
		}
		for _, v := range vectors {
			t.Run(v.name, func(t *testing.T) {
				status, delivered := driveCodeFlow(t, tg.base, mockBase, v.clientID, v.redirectURI)
				require.Emptyf(t, delivered, "a code was delivered to the unregistered redirect_uri %q", v.redirectURI)
				require.Equal(t, http.StatusBadRequest, status, "/authorize must reject the vector outright")
			})
		}

		t.Run("loopback on an ephemeral port with the exact path still works", func(t *testing.T) {
			for _, port := range []string{"54321", "1"} {
				requested := "http://127.0.0.1:" + port + "/callback"
				status, delivered := driveCodeFlow(t, tg.base, mockBase, cliClientID, requested)
				require.Equal(t, http.StatusFound, status)
				require.Truef(t, strings.HasPrefix(delivered, requested+"?"),
					"code must go back to the requested loopback URI %q, got %q", requested, delivered)
				u, err := url.Parse(delivered)
				require.NoError(t, err)
				require.NotEmpty(t, u.Query().Get("code"))
				require.Equal(t, "client-state", u.Query().Get("state"))
			}
		})

		t.Run("exact registered URI still works", func(t *testing.T) {
			status, delivered := driveCodeFlow(t, tg.base, mockBase, redirectUIClientID, redirectUICallback)
			require.Equal(t, http.StatusFound, status)
			require.Truef(t, strings.HasPrefix(delivered, redirectUICallback+"?"),
				"code must go back to the registered URI, got %q", delivered)
		})
	})
}

// redirectTestEnv is the minimal serve config for the redirect tests: the
// given client registrations plus the internal device-ui client the server
// graph always requires.
func redirectTestEnv(clients string) map[string]string {
	env := map[string]string{
		"HTTP_LISTENER":              "0.0.0.0:8000",
		"STATE_SQLITE_PATH":          "/state/state.db",
		"OIDC_ISSUER":                tempogateIssuer,
		"OIDC_ALLOW_INSECURE_ISSUER": "true", // plain-http issuer on the test network
		"OIDC_CLIENTS":               clients,
		"OIDC_ALLOWED_DOMAINS":       "example.com",
		"OIDC_GOOGLE_CLIENT_ID":      "tempogate-upstream",
		"OIDC_GOOGLE_CLIENT_SECRET":  "tempogate-upstream-secret",
		"OIDC_GOOGLE_AUTH_ENDPOINT":  mockIssuer + "/auth",
		"OIDC_GOOGLE_TOKEN_ENDPOINT": mockIssuer + "/token",
		"OIDC_GOOGLE_ISSUER_URL":     mockIssuer,
	}
	addDeviceUIServerEnv(env, tempogateIssuer)
	return env
}

type bootResult struct {
	booted bool
	base   string
	logs   string
	serve  testcontainers.Container
}

// startTempogateAllowingFailure runs migrate + serve without a readiness
// wait strategy, because the legacy subtest expects serve to exit at
// startup and a wait strategy would turn that expected outcome into an
// opaque timeout. It polls until serve either answers /readyz or exits.
func startTempogateAllowingFailure(
	ctx context.Context,
	t *testing.T,
	root, netName, alias string,
	env map[string]string,
) bootResult {
	t.Helper()
	stateVol := fmt.Sprintf("tempogate-%s-e2e-state-%d", alias, time.Now().UnixNano())
	// Registered before the containers so it runs after they are terminated
	// (t.Cleanup is LIFO).
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
	track(ctx, t, alias+"-migrate", migrate)

	serve, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:          tgImg,
			FromDockerfile: tgFrom,
			Cmd:            []string{"serve"},
			Env:            env,
			User:           "0:0",
			Mounts:         testcontainers.Mounts(testcontainers.VolumeMount(stateVol, "/state")),
			ExposedPorts:   []string{"8000/tcp"},
			Networks:       []string{netName},
			NetworkAliases: map[string][]string{netName: {alias}},
		},
		Started: true,
	})
	require.NoError(t, err, "tempogate serve")
	track(ctx, t, alias, serve)

	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		state, err := serve.State(ctx)
		require.NoError(t, err)
		if !state.Running {
			return bootResult{logs: containerLogs(ctx, t, serve)}
		}
		if p, err := serve.MappedPort(ctx, "8000/tcp"); err == nil {
			host, err := serve.Host(ctx)
			require.NoError(t, err)
			base := fmt.Sprintf("http://%s:%s", host, p.Port())
			if resp, err := http.Get(base + "/readyz"); err == nil {
				_ = resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					return bootResult{booted: true, base: base, serve: serve}
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("tempogate serve neither became ready nor exited; logs:\n%s", containerLogs(ctx, t, serve))
	return bootResult{}
}

func containerLogs(ctx context.Context, t *testing.T, c testcontainers.Container) string {
	t.Helper()
	rc, err := c.Logs(ctx)
	require.NoError(t, err)
	defer func() { _ = rc.Close() }()
	b, err := io.ReadAll(rc)
	require.NoError(t, err)
	return string(b)
}

// driveCodeFlow plays the victim's browser through /authorize, the mock
// Google consent and /callback/google, using the attacker's own PKCE
// challenge. It returns /authorize's status and, if the flow got that far,
// the final Location tempogate sent the browser to (which carries the code).
// Mock Google's approve step is pointed at tempogate's mapped host port
// because the test process cannot resolve the in-network issuer host. The
// cookie jar carries /authorize's state-binding cookie to the callback, as
// the victim's browser would.
func driveCodeFlow(t *testing.T, tgBase, mockBase, clientID, redirectURI string) (int, string) {
	t.Helper()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	noFollow := &http.Client{
		Timeout:       15 * time.Second,
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	sum := sha256.Sum256([]byte(attackerVerifier))
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {"openid email"},
		"state":                 {"client-state"},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	resp, err := noFollow.Get(tgBase + "/authorize?" + q.Encode())
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		var oauthErr struct {
			Error string `json:"error"`
		}
		require.NoErrorf(t, json.Unmarshal(body, &oauthErr), "/authorize error body: %s", body)
		require.Equal(t, "invalid_request", oauthErr.Error)
		require.Empty(t, resp.Header.Get("Location"), "a rejected /authorize must not redirect anywhere")
		return resp.StatusCode, ""
	}

	upstream, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	approve := mockBase + "/auth/approve?" + url.Values{
		"redirect_uri":   {tgBase + "/callback/google"},
		"state":          {upstream.Query().Get("state")},
		"code_challenge": {upstream.Query().Get("code_challenge")},
		"nonce":          {upstream.Query().Get("nonce")},
	}.Encode()
	resp, err = noFollow.Get(approve)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode, "mock Google approve")

	resp, err = noFollow.Get(resp.Header.Get("Location"))
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode, "/callback/google must redirect to the client")
	return http.StatusFound, resp.Header.Get("Location")
}
