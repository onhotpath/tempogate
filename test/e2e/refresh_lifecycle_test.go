//go:build e2e

// Acceptance proof for the refresh-token lifecycle (H2, M3) against the real
// tempogate image: rotation keeps working within limits, replaying a rotated
// token revokes the newer one too, removing a domain from
// OIDC_ALLOWED_DOMAINS (and restarting on the same state volume) ends the
// domain's sessions, `tempogate sessions revoke` (--email, --family,
// --subject) run inside the container ends sessions, and OIDC_REFRESH_MAX_LIFETIME is an absolute cap that
// rotation cannot extend. Before the fix every one of the negative steps
// below refreshed successfully.
//
// Refresh tokens are obtained through the whole browser chain (tempogate
// /authorize, mock Google consent, /callback/google, /token) for the public
// tempogate-cli client, exactly what `tempogate login` holds.
package e2e

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
	tcnetwork "github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
)

// familyIDPattern lifts family ids out of `tempogate sessions list` output.
var familyIDPattern = regexp.MustCompile(`(?m)^([0-9a-f]{32})\s`)

// sessionRowPattern lifts the SUBJECT column out of a `sessions list` row
// (FAMILY_ID CLIENT_ID EMAIL SUBJECT ...).
var sessionRowPattern = regexp.MustCompile(`(?m)^[0-9a-f]{32}\s+\S+\s+\S+\s+(\S+)\s`)

func TestRefreshLifecycle(t *testing.T) {
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

	tg := &restartableTempogate{ctx: ctx, owner: t, root: root, netName: netName}
	tg.start(t, redirectTestEnv(cliClientID+":http://127.0.0.1/callback"), true)

	r := &refresher{t: t, base: tg.base, httpc: &http.Client{Timeout: 15 * time.Second}}
	refresh := func(rt string) *http.Response {
		return r.post(url.Values{"client_id": {cliClientID}}, rt, "", "")
	}
	requireInvalidGrant := func(t *testing.T, resp *http.Response, msg string) {
		t.Helper()
		require.Equal(t, http.StatusBadRequest, resp.StatusCode, msg)
		require.Equal(t, "invalid_grant", decodeOAuthErrorCode(t, resp), msg)
	}

	t.Run("rotation keeps working within limits", func(t *testing.T) {
		r.t = t
		rt := r.cliRefreshToken(mockBase)
		for range 3 {
			rt = r.refreshOK(refresh(rt), cliClientID)
		}
	})

	t.Run("replaying a rotated token revokes the newer one", func(t *testing.T) {
		r.t = t
		rt1 := r.cliRefreshToken(mockBase)
		rt2 := r.refreshOK(refresh(rt1), cliClientID)

		requireInvalidGrant(t, refresh(rt1), "the replayed token")
		requireInvalidGrant(t, refresh(rt2), "the newer token after a replay")
		require.Contains(t, tg.logs(t), "refresh_token_reuse", "the replay is logged as a security event")
		require.NotContains(t, tg.logs(t), rt1, "token values never reach the log")
	})

	t.Run("sessions revoke --email ends every session of that user", func(t *testing.T) {
		r.t = t
		rt := r.cliRefreshToken(mockBase)
		rt = r.refreshOK(refresh(rt), cliClientID)

		list := tg.exec(t, "sessions", "list", "--email", allowedEmail)
		require.Contains(t, list, allowedEmail)
		require.NotContains(t, list, rt, "sessions list never prints token values")

		require.Contains(t, tg.exec(t, "sessions", "revoke", "--email", allowedEmail), "revoked")
		requireInvalidGrant(t, refresh(rt), "a revoked session")
	})

	t.Run("sessions revoke --family ends only that session", func(t *testing.T) {
		r.t = t
		rt := r.cliRefreshToken(mockBase)
		families := familyIDPattern.FindAllStringSubmatch(tg.exec(t, "sessions", "list"), -1)
		require.Len(t, families, 1, "the --email revoke above left only this session live")
		other := r.cliRefreshToken(mockBase)

		require.Contains(t, tg.exec(t, "sessions", "revoke", "--family", families[0][1]), "revoked 1 session(s)")
		requireInvalidGrant(t, refresh(rt), "the revoked family")
		r.refreshOK(refresh(other), cliClientID)
	})

	t.Run("sessions revoke --subject ends every session of that account", func(t *testing.T) {
		r.t = t
		rt := r.cliRefreshToken(mockBase)
		row := sessionRowPattern.FindStringSubmatch(tg.exec(t, "sessions", "list", "--email", allowedEmail))
		require.NotNil(t, row, "the new session is listed")
		subject := row[1]
		require.Contains(t, tg.exec(t, "sessions", "list", "--subject", subject), allowedEmail)

		require.Contains(t, tg.exec(t, "sessions", "revoke", "--subject", subject), "revoked")
		requireInvalidGrant(t, refresh(rt), "a session of the revoked subject")
		require.NotRegexp(t, familyIDPattern, tg.exec(t, "sessions", "list"), "no session of the only test account is left")
	})

	t.Run("removing the domain from the allowlist ends the session", func(t *testing.T) {
		r.t = t
		rt := r.cliRefreshToken(mockBase)

		env := redirectTestEnv(cliClientID + ":http://127.0.0.1/callback")
		env["OIDC_ALLOWED_DOMAINS"] = "other.example"
		tg.start(t, env, false)
		r.base = tg.base

		requireInvalidGrant(t, refresh(rt), "a session whose domain was removed")
		require.Contains(t, tg.logs(t), "refresh_domain_not_allowed")
	})

	t.Run("OIDC_REFRESH_MAX_LIFETIME is an absolute cap", func(t *testing.T) {
		r.t = t
		env := redirectTestEnv(cliClientID + ":http://127.0.0.1/callback")
		env["OIDC_ACCESS_TOKEN_TTL"] = "2s"
		env["OIDC_REFRESH_TOKEN_TTL"] = "10s"
		env["OIDC_REFRESH_MAX_LIFETIME"] = "15s"
		tg.start(t, env, false)
		r.base = tg.base

		before := time.Now()
		rt := r.cliRefreshToken(mockBase)
		signedIn := time.Now()
		// Refresh every 4s, well inside the 10s idle window, until 12s after
		// sign-in: each rotation succeeds but none extends the session.
		for _, at := range []time.Duration{4 * time.Second, 8 * time.Second, 12 * time.Second} {
			time.Sleep(time.Until(before.Add(at)))
			rt = r.refreshOK(refresh(rt), cliClientID)
		}
		time.Sleep(time.Until(signedIn.Add(16 * time.Second)))
		requireInvalidGrant(t, refresh(rt), "a session past its absolute lifetime")
	})
}

// restartableTempogate runs tempogate serve on one named state volume and
// can restart it with a different environment, the way an operator changes
// configuration on a running deployment.
// Containers and the volume belong to owner (the top-level test), so they
// outlive the subtest that restarts them; assertions use the caller's t.
type restartableTempogate struct {
	ctx     context.Context
	owner   *testing.T
	root    string
	netName string
	vol     string
	serve   testcontainers.Container
	base    string
	// volPrefix names the state volume; empty keeps the lifecycle test's.
	volPrefix string
}

func (tg *restartableTempogate) start(t *testing.T, env map[string]string, migrate bool) {
	t.Helper()
	ctx := tg.ctx
	img, from := builtImageSource("E2E_TEMPOGATE_IMAGE", "Dockerfile", tg.root)
	if tg.vol == "" {
		// Owned by owner and created before any container, so it is removed
		// after all of them have been terminated.
		prefix := tg.volPrefix
		if prefix == "" {
			prefix = "tempogate-lifecycle-e2e-state"
		}
		tg.vol = stateVolume(tg.owner, prefix)
	}
	mounts := testcontainers.Mounts(testcontainers.VolumeMount(tg.vol, "/state"))
	withStateBackend(ctx, tg.owner, tg.netName, env)

	if migrate {
		runMigrate(ctx, t, tg.owner, "tempogate-lifecycle-migrate", tg.netName, testcontainers.ContainerRequest{
			Image: img, FromDockerfile: from, Env: env, User: "0:0", Mounts: mounts,
		})
	}

	if tg.serve != nil {
		require.NoError(t, tg.serve.Terminate(ctx), "stop tempogate before restart")
	}
	serve, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image: img, FromDockerfile: from, Cmd: []string{"serve"}, Env: env, User: "0:0",
			Mounts:         mounts,
			ExposedPorts:   []string{"8000/tcp"},
			Networks:       []string{tg.netName},
			NetworkAliases: map[string][]string{tg.netName: {"tempogate"}},
			WaitingFor:     wait.ForHTTP("/readyz").WithPort("8000/tcp").WithStartupTimeout(2 * time.Minute),
		},
		Started: true,
	})
	track(ctx, tg.owner, "tempogate-lifecycle", serve)
	require.NoError(t, err, "tempogate serve")
	tg.serve = serve
	tg.base = mappedHTTP(ctx, t, serve, "8000")
}

// exec runs a tempogate subcommand inside the serving container, against the
// same state volume, and returns its combined output.
func (tg *restartableTempogate) exec(t *testing.T, args ...string) string {
	t.Helper()
	code, rd, err := tg.serve.Exec(tg.ctx, append([]string{"/tempogate"}, args...), tcexec.Multiplexed())
	require.NoError(t, err)
	b, err := io.ReadAll(rd)
	require.NoError(t, err)
	require.Equalf(t, 0, code, "tempogate %s: %s", strings.Join(args, " "), b)
	return string(b)
}

func (tg *restartableTempogate) logs(t *testing.T) string {
	t.Helper()
	return containerLogs(tg.ctx, t, tg.serve)
}
