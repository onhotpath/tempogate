//go:build e2e

// Acceptance proof for the HTTP server hardening shared by the public and
// admin listeners: header-size cap, read and idle timeouts, and a bounded
// graceful shutdown on SIGTERM. Runs the real tempogate image with short
// configured timeouts so each property is observable in seconds. A single
// tempogate container per scenario, no IdP or Temporal, to stay fast.
package e2e

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	hardeningReadTimeout     = 2 * time.Second
	hardeningIdleTimeout     = 3 * time.Second
	hardeningShutdownTimeout = 3 * time.Second
	// timingSlack absorbs container scheduling and docker-proxy latency.
	timingSlack = 4 * time.Second
)

var hardeningListeners = []struct{ name, port string }{
	{"public", "8000"},
	{"admin", "8081"},
}

func TestServerHardening(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e: skipped in -short")
	}
	t.Parallel()
	ctx := context.Background()
	tempogate := startHardenedTempogate(ctx, t, map[string]string{
		"SERVER_READ_TIMEOUT":  hardeningReadTimeout.String(),
		"SERVER_WRITE_TIMEOUT": "5s",
		"SERVER_IDLE_TIMEOUT":  hardeningIdleTimeout.String(),
	})

	for _, l := range hardeningListeners {
		addr := mappedAddr(ctx, t, tempogate, l.port)

		t.Run(l.name+"/oversized header is rejected with 431", func(t *testing.T) {
			// Default SERVER_MAX_HEADER_BYTES is 16 KiB (+4 KiB net/http slack).
			require.NotEqual(t, http.StatusRequestHeaderFieldsTooLarge, statusWithHeader(t, addr, 8<<10))
			require.Equal(t, http.StatusRequestHeaderFieldsTooLarge, statusWithHeader(t, addr, 64<<10))
			// The rejection did not wedge the listener.
			require.NotEqual(t, http.StatusRequestHeaderFieldsTooLarge, statusWithHeader(t, addr, 0))
		})

		t.Run(l.name+"/slow body is cut off by the read timeout", func(t *testing.T) {
			conn := dial(t, addr)
			_, err := fmt.Fprint(conn, "POST /token HTTP/1.1\r\nHost: x\r\n"+
				"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 100000\r\n\r\n")
			require.NoError(t, err)

			start := time.Now()
			closed := waitClosed(conn, hardeningReadTimeout+timingSlack, func() { _, _ = conn.Write([]byte("a")) })
			require.Truef(t, closed, "slow-body connection still open %s after the request started", time.Since(start))
		})

		t.Run(l.name+"/idle keep-alive is closed by the idle timeout", func(t *testing.T) {
			conn := dial(t, addr)
			_, err := fmt.Fprint(conn, "GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
			require.NoError(t, err)
			br := bufio.NewReader(conn)
			resp, err := http.ReadResponse(br, nil)
			require.NoError(t, err)
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			require.False(t, resp.Close, "server must offer keep-alive for this check to mean anything")

			start := time.Now()
			closed := waitClosed(conn, hardeningIdleTimeout+timingSlack, nil)
			require.Truef(t, closed, "idle keep-alive still open %s after the response", time.Since(start))
		})
	}
}

// SIGTERM with requests still in flight must stop the process within the
// configured grace, not wait on the clients. The read timeout is set far above
// the grace so the in-flight requests outlive it.
func TestServerShutdownIsBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e: skipped in -short")
	}
	t.Parallel()
	ctx := context.Background()
	tempogate := startHardenedTempogate(ctx, t, map[string]string{
		"SERVER_READ_TIMEOUT":     "2m",
		"SERVER_WRITE_TIMEOUT":    "2m",
		"SERVER_SHUTDOWN_TIMEOUT": hardeningShutdownTimeout.String(),
	})

	for _, l := range hardeningListeners {
		conn := dial(t, mappedAddr(ctx, t, tempogate, l.port))
		_, err := fmt.Fprint(conn, "POST /token HTTP/1.1\r\nHost: x\r\nContent-Length: 100000\r\n\r\na")
		require.NoError(t, err)
	}
	// Let both requests reach the handler stage before signalling.
	time.Sleep(500 * time.Millisecond)

	stopTimeout := 30 * time.Second
	start := time.Now()
	require.NoError(t, tempogate.Stop(ctx, &stopTimeout))
	elapsed := time.Since(start)

	state, err := tempogate.State(ctx)
	require.NoError(t, err)
	require.False(t, state.Running)
	require.NotEqual(t, 137, state.ExitCode, "process was SIGKILLed instead of exiting on its own")
	require.Lessf(t, elapsed, hardeningShutdownTimeout+timingSlack,
		"docker stop took %s; shutdown grace is %s", elapsed, hardeningShutdownTimeout)
}

func startHardenedTempogate(ctx context.Context, t *testing.T, extra map[string]string) testcontainers.Container {
	t.Helper()
	root := repoRoot(t)
	env := map[string]string{
		"HTTP_LISTENER": "0.0.0.0:8000",
		// Test-only: the admin listener defaults to loopback, which the host
		// cannot reach through the container's port mapping.
		"ADMIN_LISTENER":             "0.0.0.0:8081",
		"STATE_SQLITE_PATH":          "/state/state.db",
		"OIDC_ISSUER":                tempogateIssuer,
		"OIDC_ALLOW_INSECURE_ISSUER": "true", // plain-http issuer on the test network
		"OIDC_ALLOWED_DOMAINS":       "example.com",
		"OIDC_GOOGLE_CLIENT_ID":      "tempogate-upstream",
		"OIDC_GOOGLE_CLIENT_SECRET":  "tempogate-upstream-secret",
		"OIDC_GOOGLE_AUTH_ENDPOINT":  mockIssuer + "/auth",
		"OIDC_GOOGLE_TOKEN_ENDPOINT": mockIssuer + "/token",
		"OIDC_GOOGLE_ISSUER_URL":     mockIssuer,
	}
	addDeviceUIServerEnv(env, tempogateIssuer)
	for k, v := range extra {
		env[k] = v
	}
	stateVol := stateVolume(t, "tempogate-hardening-e2e-state")
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
	track(ctx, t, "tempogate-migrate", migrate)
	require.NoError(t, err, "tempogate migrate")

	tempogate, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:          tgImg,
			FromDockerfile: tgFrom,
			Cmd:            []string{"serve"},
			Env:            env,
			User:           "0:0",
			Mounts:         testcontainers.Mounts(testcontainers.VolumeMount(stateVol, "/state")),
			ExposedPorts:   []string{"8000/tcp", "8081/tcp"},
			WaitingFor:     wait.ForHTTP("/readyz").WithPort("8000/tcp").WithStartupTimeout(2 * time.Minute),
		},
		Started: true,
	})
	track(ctx, t, "tempogate", tempogate)
	require.NoError(t, err, "tempogate serve")
	return tempogate
}

func dial(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// statusWithHeader sends one request carrying a header value of size bytes
// and returns the response status.
func statusWithHeader(t *testing.T, addr string, size int) int {
	t.Helper()
	conn := dial(t, addr)
	_, err := fmt.Fprintf(conn, "GET /healthz HTTP/1.1\r\nHost: x\r\nX-Pad: %s\r\nConnection: close\r\n\r\n",
		strings.Repeat("a", size))
	require.NoError(t, err)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(10*time.Second)))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	_ = resp.Body.Close()
	return resp.StatusCode
}

// waitClosed polls conn until the peer closes it or within elapses. tick, if
// set, runs before every poll (e.g. to trickle a slow body).
func waitClosed(conn net.Conn, within time.Duration, tick func()) bool {
	deadline := time.Now().Add(within)
	buf := make([]byte, 512)
	for time.Now().Before(deadline) {
		if tick != nil {
			tick()
		}
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		_, err := conn.Read(buf)
		if err == nil {
			// A response (e.g. a 408) is fine; keep reading until close.
			continue
		}
		if errors.Is(err, os.ErrDeadlineExceeded) {
			continue
		}
		return true
	}
	return false
}
