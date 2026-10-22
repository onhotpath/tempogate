//go:build e2e

// Acceptance proof that the real tempogate image runs its non-serve
// subcommands with no server configuration at all: only STATE_SQLITE_PATH
// and a writable state volume, exactly what the Helm migrate Job and the
// docker-compose `tempogate-migrate` service provide. `serve` alone needs
// the OIDC settings; if building the server graph ever leaks back into the
// other subcommands, a fresh install's migrate step fails and this test
// catches it before a deployment does.
package e2e

import (
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestSubcommandsRunWithoutServerConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e: skipped in -short")
	}
	t.Parallel()
	ctx := context.Background()
	img, from := builtImageSource("E2E_TEMPOGATE_IMAGE", "Dockerfile", repoRoot(t))
	stateVol := fmt.Sprintf("tempogate-cli-only-e2e-state-%d", time.Now().UnixNano())

	// Order matters: keys generate refuses a stale schema, so it proves the
	// preceding migrate actually wrote to the shared volume.
	steps := [][]string{
		{"migrate"},
		{"keys", "generate"},
		{"version"},
		{"--help"},
	}
	for i, args := range steps {
		last := i == len(steps)-1
		code, logs := runOneShot(ctx, t, img, from, stateVol, last, args...)
		require.Equalf(t, 0, code, "tempogate %v must exit 0 with only STATE_SQLITE_PATH set; logs:\n%s", args, logs)
	}
}

// runOneShot runs `tempogate <args...>` to completion with only
// STATE_SQLITE_PATH set and returns its exit code and output. The container
// is removed before returning; removeVolume also drops the shared state
// volume, so pass it on the final step only.
func runOneShot(
	ctx context.Context, t *testing.T, img string, from testcontainers.FromDockerfile,
	stateVol string, removeVolume bool, args ...string,
) (int, string) {
	t.Helper()
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:          img,
			FromDockerfile: from,
			Cmd:            args,
			Env:            map[string]string{"STATE_SQLITE_PATH": "/state/state.db"},
			// Named volumes are root-owned; see web_ui_sso_test.go.
			User:       "0:0",
			Mounts:     testcontainers.Mounts(testcontainers.VolumeMount(stateVol, "/state")),
			WaitingFor: wait.ForExit().WithExitTimeout(2 * time.Minute),
		},
		Started: true,
	})
	require.NoErrorf(t, err, "tempogate %v", args)

	var opts []testcontainers.TerminateOption
	if removeVolume {
		opts = append(opts, testcontainers.RemoveVolumes(stateVol))
	}
	defer func() { require.NoError(t, c.Terminate(ctx, opts...)) }()

	state, err := c.State(ctx)
	require.NoError(t, err)
	rc, err := c.Logs(ctx)
	require.NoError(t, err)
	defer func() { _ = rc.Close() }()
	b, _ := io.ReadAll(rc)
	return state.ExitCode, string(b)
}
