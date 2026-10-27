//go:build e2e

// Acceptance proof for the Google-leg hardening (L4): the real tempogate
// image, federating to the real mock Google over a Docker network, sends
// Google its own PKCE challenge and nonce, verifies both on the way back,
// refuses a /callback/google that arrives in a browser other than the one
// that called /authorize, and recovers from a discovery outage on first use
// without a restart. mockgoogle enforces PKCE (S256 challenge at /auth,
// code_verifier at /token) and echoes the nonce, so every other e2e login
// doubles as the positive proof that the hardened leg still works.
//
// Each browser is a plain HTTP client with its own cookie jar against the
// host-mapped ports; the in-network Location hosts are rewritten, as the
// device-login driver does. Two jars model two browsers: the attacker's
// (who completes Google consent for their own account) and the victim's
// (who is lured onto the attacker's callback URL).
package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"io"
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
)

const upstreamLegLoopback = "http://127.0.0.1:43210/callback"

func TestUpstreamLegHardening(t *testing.T) {
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
	track(ctx, t, "mockgoogle", mock)
	require.NoError(t, err, "mockgoogle")
	mockBase := mappedHTTP(ctx, t, mock, "8080")

	tg := startTempogateAllowingFailure(ctx, t, root, netName, "tempogate-upstream",
		redirectTestEnv(cliClientID+":http://127.0.0.1/callback"))
	require.Truef(t, tg.booted, "tempogate must boot; logs:\n%s", tg.logs)
	b := upstreamBrowsers{tgBase: tg.base, mockBase: mockBase}

	// Must run first: tempogate resolves Google's discovery document lazily,
	// on the first callback after boot, and only that first resolution is
	// the one that used to be cached as a failure until restart.
	t.Run("discovery outage on first use recovers without a restart", func(t *testing.T) {
		setMockFaults(t, mockBase, url.Values{"discovery_down": {"true"}})
		browser := b.newBrowser(t)
		resp := browser.get(t, browser.consent(t))
		require.Equal(t, http.StatusBadGateway, resp.status, "an unreachable discovery document fails the login")

		setMockFaults(t, mockBase, url.Values{})
		require.Eventually(t, func() bool {
			browser := b.newBrowser(t)
			return browser.get(t, browser.consent(t)).status == http.StatusFound
		}, 20*time.Second, 500*time.Millisecond, "logins must recover once discovery is back, without a restart")
		waitForLogs(ctx, t, tg.serve, "discovery_unavailable")
	})

	t.Run("upstream authorize request carries S256 PKCE and a nonce", func(t *testing.T) {
		browser := b.newBrowser(t)
		upstream := browser.authorize(t)
		q := upstream.Query()
		require.Equal(t, "S256", q.Get("code_challenge_method"))
		require.Len(t, q.Get("code_challenge"), 43)
		require.NotEqual(t, downstreamChallenge(), q.Get("code_challenge"),
			"tempogate must use its own verifier, not forward the client's challenge")
		require.NotEmpty(t, q.Get("nonce"))
	})

	t.Run("callback in a second browser is rejected (login CSRF / code injection)", func(t *testing.T) {
		attacker := b.newBrowser(t)
		callbackURL := attacker.consent(t)
		u, err := url.Parse(callbackURL)
		require.NoError(t, err)
		attackerCode := u.Query().Get("code")

		victim := b.newBrowser(t)
		resp := victim.get(t, callbackURL)
		require.Equal(t, http.StatusBadRequest, resp.status,
			"a valid state presented without its binding cookie must be refused")
		require.Empty(t, resp.location, "no code may be handed to the victim's client")
		require.Contains(t, resp.body, "invalid_request")

		// A victim with a login of their own in flight holds a binding
		// cookie too, just not for the attacker's state.
		victim.authorize(t)
		resp = victim.get(t, callbackURL)
		require.Equal(t, http.StatusBadRequest, resp.status,
			"a binding cookie for another state must not unlock this one")

		// Positive control: the same callback URL in the browser that started
		// the flow succeeds, so the binding (not a stale state or a burned
		// Google code) is what turned the victim away.
		resp = attacker.get(t, callbackURL)
		require.Equal(t, http.StatusFound, resp.status)
		require.True(t, strings.HasPrefix(resp.location, upstreamLegLoopback+"?"), resp.location)

		logs := waitForLogs(ctx, t, tg.serve, "state_not_bound_to_browser")
		require.NotContains(t, logs, attackerCode, "the upstream code must never be logged")
	})

	t.Run("id_token with the wrong nonce is rejected", func(t *testing.T) {
		setMockFaults(t, mockBase, url.Values{"wrong_nonce": {"true"}})
		t.Cleanup(func() { setMockFaults(t, mockBase, url.Values{}) })

		browser := b.newBrowser(t)
		callbackURL := browser.consent(t)
		resp := browser.get(t, callbackURL)
		require.Equal(t, http.StatusBadGateway, resp.status)
		require.Empty(t, resp.location, "no code may be minted from an id_token for another login")
		require.Contains(t, resp.body, "upstream_error")

		logs := waitForLogs(ctx, t, tg.serve, "nonce_mismatch")
		u, err := url.Parse(callbackURL)
		require.NoError(t, err)
		require.NotContains(t, logs, u.Query().Get("code"), "the upstream code must never be logged")
	})

	t.Run("a hung Google token endpoint fails the login within the upstream timeout", func(t *testing.T) {
		setMockFaults(t, mockBase, url.Values{"token_hang": {"true"}})
		t.Cleanup(func() { setMockFaults(t, mockBase, url.Values{}) })

		browser := b.newBrowser(t)
		callbackURL := browser.consent(t)
		// The default browser timeout (15s) is close to tempogate's 10s
		// upstream bound; give the callback room so a hang shows up as a
		// slow answer, not as this client giving up.
		browser.client.Timeout = time.Minute
		start := time.Now()
		resp := browser.get(t, callbackURL)
		took := time.Since(start)

		require.Equal(t, http.StatusBadGateway, resp.status)
		require.Contains(t, resp.body, "upstream_error")
		require.Empty(t, resp.location, "no code may be minted without an id_token")
		require.Less(t, took, 20*time.Second, "the callback must not wait on Google past the upstream timeout")
		require.GreaterOrEqual(t, took, 9*time.Second, "the call is given its full budget before failing")

		logs := waitForLogs(ctx, t, tg.serve, "code_exchange_failed")
		require.Regexp(t, `"timeout":true`, logs, "the log must say the call timed out")
	})

	t.Run("mock Google refuses an authorize request without PKCE", func(t *testing.T) {
		// Guards the mock itself: if it stopped enforcing PKCE, the positive
		// e2e logins would no longer prove tempogate sends it.
		resp, err := http.Get(mockBase + "/auth?" + url.Values{
			"client_id":    {"tempogate-upstream"},
			"redirect_uri": {tempogateIssuer + "/callback/google"},
			"state":        {"s"},
			"nonce":        {"n"},
		}.Encode())
		require.NoError(t, err)
		_ = resp.Body.Close()
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}

// upstreamBrowsers mints independent browsers (each its own cookie jar)
// against one tempogate and one mock Google.
type upstreamBrowsers struct {
	tgBase, mockBase string
}

type upstreamBrowser struct {
	upstreamBrowsers
	client *http.Client
}

type upstreamResponse struct {
	status   int
	location string
	body     string
}

func (b upstreamBrowsers) newBrowser(t *testing.T) *upstreamBrowser {
	t.Helper()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	return &upstreamBrowser{
		upstreamBrowsers: b,
		client: &http.Client{
			Timeout:       15 * time.Second,
			Jar:           jar,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// authorize starts a CLI-loopback login and returns the upstream (mock
// Google) authorization URL, rewritten to the host-mapped mock port.
func (br *upstreamBrowser) authorize(t *testing.T) *url.URL {
	t.Helper()
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {cliClientID},
		"redirect_uri":          {upstreamLegLoopback},
		"scope":                 {"openid email"},
		"state":                 {"client-state"},
		"code_challenge":        {downstreamChallenge()},
		"code_challenge_method": {"S256"},
	}
	resp := br.get(t, br.tgBase+"/authorize?"+q.Encode())
	require.Equalf(t, http.StatusFound, resp.status, "/authorize: %s", resp.body)
	u, err := url.Parse(strings.Replace(resp.location, mockIssuer, br.mockBase, 1))
	require.NoError(t, err)
	return u
}

// consent runs /authorize and the mock Google consent, and returns the
// /callback/google URL (host-mapped) Google sent the browser back to,
// without following it.
func (br *upstreamBrowser) consent(t *testing.T) string {
	t.Helper()
	resp := br.get(t, br.authorize(t).String())
	require.Equalf(t, http.StatusOK, resp.status, "mock /auth: %s", resp.body)
	href := mockApproveHrefPattern.FindStringSubmatch(resp.body)
	require.NotEmptyf(t, href, "no approve link on the consent page:\n%s", resp.body)

	resp = br.get(t, br.mockBase+href[1])
	require.Equal(t, http.StatusFound, resp.status, "mock approve")
	require.Truef(t, strings.HasPrefix(resp.location, tempogateIssuer+"/callback/google?"), resp.location)
	return strings.Replace(resp.location, tempogateIssuer, br.tgBase, 1)
}

func (br *upstreamBrowser) get(t *testing.T, rawURL string) upstreamResponse {
	t.Helper()
	resp, err := br.client.Get(rawURL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return upstreamResponse{status: resp.StatusCode, location: resp.Header.Get("Location"), body: string(body)}
}

func setMockFaults(t *testing.T, mockBase string, form url.Values) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, mockBase+"/_control/faults", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
}

// downstreamChallenge is the CLI's own PKCE challenge on the downstream leg;
// tempogate must not reuse it upstream.
func downstreamChallenge() string {
	sum := sha256.Sum256([]byte(attackerVerifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
