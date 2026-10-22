//go:build e2e

// Acceptance proofs for the configuration hardening against the real image:
// `serve` refuses a plain-http, non-loopback OIDC_ISSUER unless the
// development opt-in OIDC_ALLOW_INSECURE_ISSUER is set; an explicit
// `--config` file is honoured by every subcommand and is fatal when missing;
// and the image boots under a uid other than its default, whose working
// directory (/home/nonroot) it cannot read.
package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// serverEnv is the minimal environment `serve` needs to boot for issuer.
func serverEnv(issuer string) map[string]string {
	env := map[string]string{
		"HTTP_LISTENER":             "0.0.0.0:8000",
		"STATE_SQLITE_PATH":         "/state/state.db",
		"OIDC_ISSUER":               issuer,
		"OIDC_ALLOWED_DOMAINS":      "example.com",
		"OIDC_GOOGLE_CLIENT_ID":     "tempogate-upstream",
		"OIDC_GOOGLE_CLIENT_SECRET": "tempogate-upstream-secret",
	}
	addDeviceUIServerEnv(env, issuer)
	return env
}

// runToExit runs req to completion and returns its exit code and output.
func runToExit(ctx context.Context, t *testing.T, name string, req testcontainers.ContainerRequest) (int, string) {
	t.Helper()
	req.WaitingFor = wait.ForExit().WithExitTimeout(2 * time.Minute)
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{ContainerRequest: req, Started: true})
	if c != nil {
		// Also on a wait timeout, so a container that never exits is not leaked.
		defer func() { require.NoError(t, c.Terminate(ctx)) }()
	}
	require.NoError(t, err, name)

	state, err := c.State(ctx)
	require.NoError(t, err)
	return state.ExitCode, containerLogs(ctx, t, c)
}

// startServing starts req and waits for /readyz; it returns the mapped base
// URL and the container (terminated when the test ends).
func startServing(ctx context.Context, t *testing.T, name string, req testcontainers.ContainerRequest) (string, testcontainers.Container) {
	t.Helper()
	req.ExposedPorts = []string{"8000/tcp"}
	req.WaitingFor = wait.ForHTTP("/readyz").WithPort("8000/tcp").WithStartupTimeout(2 * time.Minute)
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{ContainerRequest: req, Started: true})
	track(ctx, t, name, c)
	require.NoError(t, err, name)
	return mappedHTTP(ctx, t, c, "8000"), c
}

// discoveredIssuer fetches the discovery document under issuerPath (the
// issuer's path component) and returns its advertised issuer.
func discoveredIssuer(t *testing.T, base, issuerPath string) string {
	t.Helper()
	resp, err := http.Get(base + issuerPath + "/.well-known/openid-configuration")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var doc struct {
		Issuer string `json:"issuer"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&doc))
	return doc.Issuer
}

func TestServeRefusesPlainHTTPIssuer(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("e2e: skipped in -short")
	}
	ctx := context.Background()
	img, from := builtImageSource("E2E_TEMPOGATE_IMAGE", "Dockerfile", repoRoot(t))
	vol := stateVolume(t, "insecure-issuer")
	env := serverEnv(tempogateIssuer) // http://tempogate:8000
	req := func(cmd ...string) testcontainers.ContainerRequest {
		return testcontainers.ContainerRequest{
			Image:          img,
			FromDockerfile: from,
			Cmd:            cmd,
			Env:            env,
			User:           "0:0", // named volumes are root-owned; see web_ui_sso_test.go
			Mounts:         testcontainers.Mounts(testcontainers.VolumeMount(vol, "/state")),
		}
	}

	// migrate never builds the issuer, so an insecure one does not stop it.
	code, logs := runToExit(ctx, t, "tempogate migrate", req("migrate"))
	require.Equalf(t, 0, code, "migrate must ignore the issuer; logs:\n%s", logs)

	code, logs = runToExit(ctx, t, "tempogate serve", req("serve"))
	require.NotEqualf(t, 0, code, "serve must refuse a plain-http issuer; logs:\n%s", logs)
	// zap escapes the quotes inside the logged error.
	require.Contains(t, logs, `OIDC_ISSUER \"http://tempogate:8000\" must use https`)
	require.Contains(t, logs, "OIDC_ALLOW_INSECURE_ISSUER")

	env["OIDC_ALLOW_INSECURE_ISSUER"] = "true"
	base, c := startServing(ctx, t, "tempogate", req("serve"))
	require.Equal(t, tempogateIssuer, discoveredIssuer(t, base, ""))
	require.Contains(t, containerLogs(ctx, t, c), "insecure OIDC issuer allowed")
}

// TestServeRefusesWithoutAuthorization is the deny-by-default upgrade
// guard on the real image: a configuration that used to make every admitted
// user cluster admin now stops serve at startup and names the fix.
func TestServeRefusesWithoutAuthorization(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("e2e: skipped in -short")
	}
	ctx := context.Background()
	img, from := builtImageSource("E2E_TEMPOGATE_IMAGE", "Dockerfile", repoRoot(t))
	vol := stateVolume(t, "no-authz")
	env := serverEnv(tempogateIssuer)
	env["OIDC_ALLOW_INSECURE_ISSUER"] = "true"
	delete(env, "OIDC_AUTHZ_RULES_0")
	req := func(cmd ...string) testcontainers.ContainerRequest {
		return testcontainers.ContainerRequest{
			Image: img, FromDockerfile: from, Cmd: cmd, Env: env, User: "0:0",
			Mounts: testcontainers.Mounts(testcontainers.VolumeMount(vol, "/state")),
		}
	}

	code, logs := runToExit(ctx, t, "tempogate migrate", req("migrate"))
	require.Equalf(t, 0, code, "migrate needs no authorization; logs:\n%s", logs)

	code, logs = runToExit(ctx, t, "tempogate serve", req("serve"))
	require.NotEqualf(t, 0, code, "serve must refuse to start; logs:\n%s", logs)
	require.Contains(t, logs, "no authorization configured")
	require.Contains(t, logs, "OIDC_AUTHZ_DEFAULT_PERMISSIONS=temporal-system:admin")
	require.Contains(t, logs, "docs/configuration.md#upgrading-to-deny-by-default-authorization")
}

func TestConfigFlagSelectsMountedFile(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("e2e: skipped in -short")
	}
	ctx := context.Background()
	img, from := builtImageSource("E2E_TEMPOGATE_IMAGE", "Dockerfile", repoRoot(t))
	vol := stateVolume(t, "config-flag")

	// Everything comes from the file: the container gets no environment, so
	// the state path, listener and issuer below can only have come from it.
	const (
		cfgPath = "/etc/tempogate/tempogate.yaml"
		issuer  = "https://tempogate.example.com/idp"
	)
	env := serverEnv(issuer)
	yaml := fmt.Sprintf(`http:
  listener: 0.0.0.0:8000
state:
  sqlite:
    path: /state/from-config.db
oidc:
  issuer: %s
  clients: %q
  client_secrets: %q
  session_signing_key: %s
  allowed_domains: example.com
  authz:
    rules:
      - %q
`, issuer, env["OIDC_CLIENTS"], env["OIDC_CLIENT_SECRETS"], env["OIDC_SESSION_SIGNING_KEY"], e2eAdminRule)
	req := func(cmd ...string) testcontainers.ContainerRequest {
		return testcontainers.ContainerRequest{
			Image:          img,
			FromDockerfile: from,
			Cmd:            cmd,
			User:           "0:0",
			Mounts:         testcontainers.Mounts(testcontainers.VolumeMount(vol, "/state")),
			Files: []testcontainers.ContainerFile{{
				Reader:            strings.NewReader(yaml),
				ContainerFilePath: cfgPath,
				FileMode:          0o644,
			}},
		}
	}

	code, logs := runToExit(ctx, t, "tempogate migrate", req("migrate", "--config", cfgPath))
	require.Equalf(t, 0, code, "logs:\n%s", logs)
	require.Contains(t, logs, "/state/from-config.db", "migrate must use the state path from --config")

	base, _ := startServing(ctx, t, "tempogate", req("--config="+cfgPath, "serve"))
	require.Equal(t, issuer, discoveredIssuer(t, base, "/idp"))

	// An explicitly requested file that is missing is fatal, for any
	// subcommand.
	code, logs = runToExit(ctx, t, "tempogate version", req("version", "--config", "/etc/tempogate/missing.yaml"))
	require.NotEqualf(t, 0, code, "logs:\n%s", logs)
	require.Contains(t, logs, "/etc/tempogate/missing.yaml")
}

// The image's default user is nonroot (65532) and its working directory is
// that user's home. Platforms that assign a random uid (OpenShift, a
// securityContext.runAsUser) leave the process unable to read it; the
// implicit ./application.yaml lookup must skip it rather than fail.
func TestServeAsNonDefaultUID(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("e2e: skipped in -short")
	}
	ctx := context.Background()
	root := repoRoot(t)
	img, from := builtImageSource("E2E_TEMPOGATE_IMAGE", "Dockerfile", root)
	vol := stateVolume(t, "non-default-uid")
	const uid = "1234:1234"

	// The distroless image has no shell; borrow the CLI client image's to
	// hand the root-owned volume to the arbitrary uid, as a platform's fsGroup
	// or volume permissions would.
	cliImg, cliFrom := builtImageSource("E2E_CLICLIENT_IMAGE", "test/e2e/cliclient/Dockerfile", root)
	code, logs := runToExit(ctx, t, "chown state volume", testcontainers.ContainerRequest{
		Image:          cliImg,
		FromDockerfile: cliFrom,
		Entrypoint:     []string{"chown", uid, "/state"},
		User:           "0:0",
		Mounts:         testcontainers.Mounts(testcontainers.VolumeMount(vol, "/state")),
	})
	require.Equalf(t, 0, code, "logs:\n%s", logs)

	issuer := "https://tempogate.example.com"
	req := func(cmd ...string) testcontainers.ContainerRequest {
		return testcontainers.ContainerRequest{
			Image:          img,
			FromDockerfile: from,
			Cmd:            cmd,
			Env:            serverEnv(issuer),
			User:           uid,
			Mounts:         testcontainers.Mounts(testcontainers.VolumeMount(vol, "/state")),
		}
	}

	code, logs = runToExit(ctx, t, "tempogate migrate", req("migrate"))
	require.Equalf(t, 0, code, "migrate as uid %s; logs:\n%s", uid, logs)
	require.Contains(t, logs, "skipping unreadable config file", "the uid must not be able to read the image's cwd")

	base, _ := startServing(ctx, t, "tempogate", req("serve"))
	require.Equal(t, issuer, discoveredIssuer(t, base, ""))
}
