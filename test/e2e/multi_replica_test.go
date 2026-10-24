//go:build e2e

// Acceptance proof for running tempogate as several replicas over one
// PostgreSQL state store (L15 D3-3): two `serve` containers, each with its
// own `migrate` run first the way the chart's per-pod initContainer does,
// boot together on one empty database and behave as one server.
//
//   - Both replicas publish the same single signing key: the migrations and
//     the first-boot key generation serialise on advisory locks.
//   - An authorization code minted on A is redeemed on B.
//   - A refresh on A followed by a replay of the rotated token on B is
//     detected as reuse, and the family's newer token is revoked on A too.
//   - An integration key revoked on A is refused on B while B's denylist
//     cache still holds an "active" answer for it, which only the change
//     feed (LISTEN/NOTIFY) can invalidate inside keys.DefaultDenylistTTL.
//   - A signing key generated on A is in B's JWKS long before B's periodic
//     reload, again only through the change feed.
//
// The test always runs on PostgreSQL, whatever E2E_STATE_DRIVER says:
// SQLite allows one writer, so it has no multi-replica mode.
package e2e

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcnetwork "github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/onhotpath/tempogate/keys"
)

// replicaReloadInterval is KEYS_RELOAD_INTERVAL on both replicas: far longer
// than the test, so a key change seen on the other replica within
// feedDeadline can only have come through the change feed.
const replicaReloadInterval = 10 * time.Minute

// feedDeadline bounds how long a change written on one replica may take to
// reach the other. It is a third of keys.DefaultDenylistTTL, the earliest
// the periodic backstop could deliver a revocation.
const feedDeadline = keys.DefaultDenylistTTL / 3

type replica struct {
	serve     testcontainers.Container
	publicURL string
	adminURL  string
}

func TestMultiReplica(t *testing.T) {
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

	env := redirectTestEnv(cliClientID + ":http://127.0.0.1/callback")
	env["ADMIN_LISTENER"] = "0.0.0.0:8081"
	env["KEYS_RELOAD_INTERVAL"] = replicaReloadInterval.String()
	addAdminAuthEnv(ctx, t, env, false)
	withPostgresState(ctx, t, netName, env)

	a, b := startReplicas(ctx, t, root, netName, env)

	t.Run("replicas booting together share one signing key", func(t *testing.T) {
		kidsA, kidsB := jwksKids(t, a.publicURL), jwksKids(t, b.publicURL)
		require.Len(t, kidsA, 1, "one replica generates the first key, the other loads it")
		require.Equal(t, kidsA, kidsB)
	})

	// on returns a token-endpoint client for replica r, reporting to t.
	on := func(t *testing.T, r replica) *refresher {
		return &refresher{t: t, base: r.publicURL, httpc: &http.Client{Timeout: 15 * time.Second}}
	}
	refresh := func(t *testing.T, r replica, rt string) *http.Response {
		return on(t, r).post(url.Values{"client_id": {cliClientID}}, rt, "", "")
	}
	requireInvalidGrant := func(t *testing.T, resp *http.Response, msg string) {
		t.Helper()
		require.Equal(t, http.StatusBadRequest, resp.StatusCode, msg)
		require.Equal(t, "invalid_grant", decodeOAuthErrorCode(t, resp), msg)
	}

	t.Run("a refresh replayed on the other replica is reuse", func(t *testing.T) {
		// Sign in on A and redeem the code on B.
		rt1 := on(t, b).refreshOK(on(t, b).postToken(url.Values{
			"grant_type":    {"authorization_code"},
			"client_id":     {cliClientID},
			"code":          {on(t, a).code(mockBase, cliClientID, refreshCLICallback)},
			"redirect_uri":  {refreshCLICallback},
			"code_verifier": {attackerVerifier},
		}, "", ""), cliClientID)

		rt2 := on(t, a).refreshOK(refresh(t, a, rt1), cliClientID)
		requireInvalidGrant(t, refresh(t, b, rt1), "the rotated token replayed on B")
		waitForLogs(ctx, t, b.serve, "refresh_token_reuse")
		requireInvalidGrant(t, refresh(t, a, rt2), "the newer token on A after the replay on B")
	})

	t.Run("a key revoked on one replica is refused on the other", func(t *testing.T) {
		key := mintIntegrationKey(t, a.adminURL, adminCreateBody{Namespace: "orders", Role: "read", Owner: "e2e-replicas"})
		// B verifies the key once, caching "not revoked" for
		// keys.DefaultDenylistTTL.
		require.Equal(t, http.StatusOK, userinfoStatus(t, b.publicURL, key.JWT), "B accepts a key minted on A")

		revokeIntegrationKey(t, a.adminURL, key.ID)
		revoked := time.Now()
		require.Equal(t, http.StatusUnauthorized, userinfoStatus(t, a.publicURL, key.JWT), "A refuses the key it revoked at once")
		require.Eventually(t, func() bool {
			return userinfoStatus(t, b.publicURL, key.JWT) == http.StatusUnauthorized
		}, feedDeadline, 100*time.Millisecond, "B must learn of the revocation through the change feed, well before its cached answer expires")
		t.Logf("B refused the revoked key %s after the revocation on A", time.Since(revoked).Round(time.Millisecond))
	})

	t.Run("a signing key generated on one replica is published by the other", func(t *testing.T) {
		out := execTempogate(ctx, t, a.serve, "keys", "generate", "--force")
		kid := regexp.MustCompile(`kid=(\S+)`).FindStringSubmatch(out)
		require.Lenf(t, kid, 2, "keys generate output: %s", out)
		require.Eventually(t, func() bool { return slices.Contains(jwksKids(t, b.publicURL), kid[1]) },
			feedDeadline, 100*time.Millisecond, "B must publish the new key through the change feed, long before KEYS_RELOAD_INTERVAL")
	})
}

// startReplicas starts replicas a and b on netName at the same time, each
// running `tempogate migrate` and then `tempogate serve` against the shared
// state database in env, and waits until both are ready.
func startReplicas(ctx context.Context, t *testing.T, root, netName string, env map[string]string) (replica, replica) {
	t.Helper()
	img, from := builtImageSource("E2E_TEMPOGATE_IMAGE", "Dockerfile", root)
	names := []string{"tempogate-a", "tempogate-b"}
	replicas := make([]replica, len(names))
	errs := make([]error, len(names))
	var wg sync.WaitGroup
	for i, name := range names {
		wg.Go(func() {
			replicas[i], errs[i] = startReplica(ctx, name, img, from, netName, maps.Clone(env),
				func(n string, c testcontainers.Container) { track(ctx, t, n, c) })
		})
	}
	wg.Wait()
	require.NoError(t, errors.Join(errs...), "start replicas")
	for i := range replicas {
		replicas[i].publicURL = mappedHTTP(ctx, t, replicas[i].serve, "8000")
		replicas[i].adminURL = mappedHTTP(ctx, t, replicas[i].serve, "8081")
	}
	return replicas[0], replicas[1]
}

// startReplica runs migrate to completion, then serve. It reports failures
// as errors rather than failing t, because it runs off the test goroutine.
func startReplica(
	ctx context.Context, name, img string, from testcontainers.FromDockerfile, netName string,
	env map[string]string, track func(string, testcontainers.Container),
) (replica, error) {
	migrate, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image: img, FromDockerfile: from, Cmd: []string{"migrate"}, Env: env,
			Networks:   []string{netName},
			WaitingFor: wait.ForExit().WithExitTimeout(2 * time.Minute),
		},
		Started: true,
	})
	track(name+"-migrate", migrate)
	if err != nil {
		return replica{}, fmt.Errorf("%s migrate: %w", name, err)
	}
	st, err := migrate.State(ctx)
	if err != nil {
		return replica{}, fmt.Errorf("%s migrate: %w", name, err)
	}
	if st.ExitCode != 0 {
		return replica{}, fmt.Errorf("%s migrate exited %d", name, st.ExitCode)
	}

	serve, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image: img, FromDockerfile: from, Cmd: []string{"serve"}, Env: env,
			ExposedPorts:   []string{"8000/tcp", "8081/tcp"},
			Networks:       []string{netName},
			NetworkAliases: map[string][]string{netName: {name}},
			WaitingFor: wait.ForAll(
				wait.ForHTTP("/readyz").WithPort("8000/tcp"),
				wait.ForHTTP("/admin/healthz").WithPort("8081/tcp"),
			).WithStartupTimeoutDefault(2 * time.Minute),
		},
		Started: true,
	})
	track(name, serve)
	if err != nil {
		return replica{}, fmt.Errorf("%s serve: %w", name, err)
	}
	return replica{serve: serve}, nil
}
