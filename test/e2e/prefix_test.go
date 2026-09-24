//go:build e2e

// Acceptance proof for sub-path hosting: the real tempogate image, run with an
// OIDC_ISSUER that carries a path, serves its entire OIDC surface under that
// path while /healthz and /readyz stay at the root (k8s-probe-only, never
// path-routed). This closes the real-binary/fx/config gap that the api-package
// httptest coverage cannot reach; the authorize→Google→token loopback under a
// prefix is covered by the oidc/api unit guards plus the unchanged root-issuer
// e2e (regression). Deliberately a single container — no mock Google / Temporal
// / headless Chrome — so it stays a fast, targeted check.
package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestSubPathIssuerHosting(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e: skipped in -short")
	}
	ctx := context.Background()
	root := repoRoot(t)

	const basePath = "/idp"
	issuer := tempogateIssuer + basePath // http://tempogate:8000/idp

	env := map[string]string{
		"HTTP_LISTENER":              "0.0.0.0:8000",
		"STATE_SQLITE_PATH":          "/state/state.db",
		"OIDC_ISSUER":                issuer,
		"OIDC_CLIENTS":               "ui:https://app.example.com/",
		"OIDC_ALLOWED_DOMAINS":       "example.com",
		"OIDC_GOOGLE_CLIENT_ID":      "tempogate-upstream",
		"OIDC_GOOGLE_CLIENT_SECRET":  "tempogate-upstream-secret",
		"OIDC_GOOGLE_AUTH_ENDPOINT":  mockIssuer + "/auth",
		"OIDC_GOOGLE_TOKEN_ENDPOINT": mockIssuer + "/token",
		"OIDC_GOOGLE_ISSUER_URL":     mockIssuer,
	}
	// Path-prefixed issuer ⇒ the device-ui's registered callback also
	// lives under the prefix; pass the prefixed issuer so the registration
	// matches what the verification-UI handler builds.
	addDeviceUIServerEnv(env, issuer)
	stateVol := fmt.Sprintf("tempogate-prefix-e2e-state-%d", time.Now().UnixNano())
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

	// Readiness probes /readyz — at the ROOT even in base-path mode. That this
	// wait succeeds is itself the proof health stays unprefixed in the real
	// binary.
	tempogate, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:          tgImg,
			FromDockerfile: tgFrom,
			Cmd:            []string{"serve"},
			Env:            env,
			User:           "0:0",
			Mounts:         testcontainers.Mounts(testcontainers.VolumeMount(stateVol, "/state")),
			ExposedPorts:   []string{"8000/tcp"},
			WaitingFor:     wait.ForHTTP("/readyz").WithPort("8000/tcp").WithStartupTimeout(2 * time.Minute),
		},
		Started: true,
	})
	require.NoError(t, err, "tempogate serve")
	track(ctx, t, "tempogate", tempogate)

	base := mappedHTTP(ctx, t, tempogate, "8000")

	getStatus := func(path string) (int, []byte) {
		t.Helper()
		resp, err := http.Get(base + path)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, b
	}

	// OIDC discovery is served UNDER the prefix and advertises issuer-relative
	// (prefixed) endpoints — the iss/endpoint/served-path lockstep.
	code, body := getStatus(basePath + "/.well-known/openid-configuration")
	require.Equalf(t, http.StatusOK, code, "discovery under prefix: %s", body)
	var doc struct {
		Issuer                string `json:"issuer"`
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
		UserinfoEndpoint      string `json:"userinfo_endpoint"`
		JwksURI               string `json:"jwks_uri"`
	}
	require.NoError(t, json.Unmarshal(body, &doc))
	require.Equal(t, issuer, doc.Issuer)
	require.Equal(t, issuer+"/authorize", doc.AuthorizationEndpoint)
	require.Equal(t, issuer+"/token", doc.TokenEndpoint)
	require.Equal(t, issuer+"/userinfo", doc.UserinfoEndpoint)
	require.Equal(t, issuer+"/.well-known/jwks.json", doc.JwksURI)

	jc, _ := getStatus(basePath + "/.well-known/jwks.json")
	require.Equal(t, http.StatusOK, jc, "JWKS served under the prefix")

	// Health stays at the root regardless of the prefix.
	hc, _ := getStatus("/healthz")
	require.Equal(t, http.StatusOK, hc, "/healthz must stay at root")
	yc, _ := getStatus("/readyz")
	require.Equal(t, http.StatusOK, yc, "/readyz must stay at root")

	// The OIDC surface must NOT answer at the root, and health must NOT move
	// under the prefix.
	rc, _ := getStatus("/.well-known/openid-configuration")
	require.Equal(t, http.StatusNotFound, rc, "discovery must not be at root in base-path mode")
	ph, _ := getStatus(basePath + "/healthz")
	require.Equal(t, http.StatusNotFound, ph, "/healthz must not move under the prefix")
}
