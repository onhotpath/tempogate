//go:build e2e

// Acceptance proof for 5xx sanitization: the real tempogate image loses its
// state tables underneath a running server (the shape of a corrupted or
// half-migrated SQLite file), and anonymous callers of /authorize, /token,
// and the device UI must see a generic error that names a request id, never
// the SQLite text or the DB path. The operator side of the contract is the
// container log: it must carry that request id next to the real cause.
//
// The state dir is a host bind mount and the containers run as the host
// uid/gid, so the test process can open the same SQLite file and drop the
// tables after boot. Deliberately a single container, like prefix_test.go.
package e2e

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	_ "modernc.org/sqlite"
)

// requestIDHeader is spelled out rather than imported so the test pins the
// wire contract clients see.
const requestIDHeader = "X-Request-Id"

func TestServerErrorsAreSanitized(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("e2e: skipped in -short")
	}
	ctx := context.Background()
	root := repoRoot(t)

	stateDir := t.TempDir()
	user := fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid())
	bindState := func(hc *container.HostConfig) { hc.Binds = append(hc.Binds, stateDir+":/state") }
	// The image WORKDIR is /home/nonroot, which only uid 65532 can read; the
	// config loader stats application.yaml there, so a host uid must start
	// elsewhere. Set here, not via ContainerRequest.User: a ConfigModifier
	// takes precedence over the deprecated request fields.
	runAsHostUser := func(c *container.Config) {
		c.User = user
		c.WorkingDir = "/"
	}

	env := map[string]string{
		"HTTP_LISTENER":              "0.0.0.0:8000",
		"STATE_SQLITE_PATH":          "/state/state.db",
		"OIDC_ISSUER":                tempogateIssuer,
		"OIDC_CLIENTS":               "ui:https://app.example.com/cb",
		"OIDC_ALLOWED_DOMAINS":       "example.com",
		"OIDC_GOOGLE_CLIENT_ID":      "tempogate-upstream",
		"OIDC_GOOGLE_CLIENT_SECRET":  "tempogate-upstream-secret",
		"OIDC_GOOGLE_AUTH_ENDPOINT":  "http://unused.invalid/auth",
		"OIDC_GOOGLE_TOKEN_ENDPOINT": "http://unused.invalid/token",
		"OIDC_GOOGLE_ISSUER_URL":     "http://unused.invalid",
	}
	addDeviceUIServerEnv(env, tempogateIssuer)
	tgImg, tgFrom := builtImageSource("E2E_TEMPOGATE_IMAGE", "Dockerfile", root)

	migrate, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:              tgImg,
			FromDockerfile:     tgFrom,
			Cmd:                []string{"migrate"},
			Env:                env,
			HostConfigModifier: bindState,
			ConfigModifier:     runAsHostUser,
			WaitingFor:         wait.ForExit().WithExitTimeout(2 * time.Minute),
		},
		Started: true,
	})
	require.NoError(t, err, "tempogate migrate")
	track(ctx, t, "tempogate-migrate", migrate)

	tempogate, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:              tgImg,
			FromDockerfile:     tgFrom,
			Cmd:                []string{"serve"},
			Env:                env,
			HostConfigModifier: bindState,
			ConfigModifier:     runAsHostUser,
			ExposedPorts:       []string{"8000/tcp"},
			WaitingFor:         wait.ForHTTP("/readyz").WithPort("8000/tcp").WithStartupTimeout(2 * time.Minute),
		},
		Started: true,
	})
	require.NoError(t, err, "tempogate serve")
	track(ctx, t, "tempogate", tempogate)
	base := mappedHTTP(ctx, t, tempogate, "8000")

	db, err := sql.Open("sqlite", "file:"+filepath.Join(stateDir, "state.db")+"?_pragma=busy_timeout(5000)")
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, `DROP TABLE auth_requests; DROP TABLE auth_codes; DROP TABLE device_codes;`)
	require.NoError(t, err, "drop state tables under the running server")
	require.NoError(t, db.Close())

	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	form := func(path string, v url.Values) (*http.Response, error) {
		return noRedirect.Post(base+path, "application/x-www-form-urlencoded", strings.NewReader(v.Encode()))
	}
	authorizeQ := url.Values{
		"response_type": {"code"}, "client_id": {"ui"}, "redirect_uri": {"https://app.example.com/cb"},
		"scope": {"openid email"}, "state": {"s"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
	}

	cases := []struct {
		name     string
		do       func() (*http.Response, error)
		wantHTML bool
	}{
		{"authorize", func() (*http.Response, error) { return noRedirect.Get(base + "/authorize?" + authorizeQ.Encode()) }, false},
		{"token", func() (*http.Response, error) {
			return form("/token", url.Values{
				"grant_type": {"authorization_code"}, "code": {"e2e-auth-code-secret"}, "client_id": {"ui"},
				"redirect_uri":  {"https://app.example.com/cb"},
				"code_verifier": {"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"},
			})
		}, false},
		{"device ui", func() (*http.Response, error) {
			return form("/device", url.Values{"user_code": {"BCDF-GHJK"}})
		}, true},
	}

	var reqIDs []string
	for _, tc := range cases {
		resp, err := tc.do()
		require.NoError(t, err, tc.name)
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		body := string(raw)
		reqID := resp.Header.Get(requestIDHeader)

		require.Equalf(t, http.StatusInternalServerError, resp.StatusCode, "%s: %s", tc.name, body)
		for _, leak := range []string{"sqlite", "SQL logic error", "no such table", "/state", "state.db"} {
			require.NotContainsf(t, body, leak, "%s: response leaks %q:\n%s", tc.name, leak, body)
		}
		require.NotEmptyf(t, reqID, "%s: response must carry %s", tc.name, requestIDHeader)
		require.Containsf(t, body, reqID, "%s: body must name the request id", tc.name)
		if tc.wantHTML {
			require.Truef(t, strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html"),
				"%s: device UI 5xx must be an HTML page, got %q", tc.name, resp.Header.Get("Content-Type"))
		} else {
			var p struct {
				Detail string            `json:"detail"`
				Errors []json.RawMessage `json:"errors"`
			}
			require.NoErrorf(t, json.Unmarshal(raw, &p), "%s: problem document", tc.name)
			require.Emptyf(t, p.Errors, "%s: no per-error detail on 5xx", tc.name)
		}
		reqIDs = append(reqIDs, reqID)
	}

	// The server logs every 5xx with its request id and the real cause. Poll
	// briefly: the container log stream is asynchronous to the response.
	require.Eventually(t, func() bool {
		logs := containerLogs(ctx, t, tempogate)
		for _, id := range reqIDs {
			if !logLineHas(logs, id, "no such table") {
				return false
			}
		}
		return !strings.Contains(logs, "e2e-auth-code-secret")
	}, 15*time.Second, 250*time.Millisecond, "container logs must carry each request id with the SQLite cause:\n%s",
		containerLogs(ctx, t, tempogate))
}

func logLineHas(logs string, needles ...string) bool {
	for line := range strings.SplitSeq(logs, "\n") {
		ok := true
		for _, n := range needles {
			ok = ok && strings.Contains(line, n)
		}
		if ok {
			return true
		}
	}
	return false
}
