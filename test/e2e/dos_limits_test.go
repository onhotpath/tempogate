//go:build e2e

// Acceptance proof for H4 against the real tempogate image: an anonymous
// caller can no longer grow the state database with oversized /authorize
// or /device_authorization parameters (400, nothing written), a burst past
// the per-address limit gets 429 with Retry-After, and the reaper deletes
// expired rows (an unredeemed auth code, a rotated refresh-token family
// past its absolute lifetime) while keeping the family's tombstone until
// then. A CLI code-flow login and refresh still work under the limits.
// Before the fix the oversized requests were stored (about 18 MB for 20
// requests), no request was ever refused for rate, and nothing deleted an
// expired row.
//
// The oversized /authorize values stay under 16 KiB so the request line
// fits a capped MaxHeaderBytes too: the 400 comes from the parameter caps,
// not the header limit.
package e2e

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcnetwork "github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
	_ "modernc.org/sqlite"
)

func TestDoSLimits(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e: skipped in -short")
	}
	t.Parallel()
	ctx := context.Background()
	root := repoRoot(t)

	net, err := tcnetwork.New(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = net.Remove(ctx) })

	mockImg, mockFrom := builtImageSource("E2E_MOCKGOOGLE_IMAGE", "test/e2e/mockgoogle/Dockerfile", root)
	mock, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:          mockImg,
			FromDockerfile: mockFrom,
			Env:            map[string]string{"MOCK_ISSUER": mockIssuer},
			ExposedPorts:   []string{"8080/tcp"},
			Networks:       []string{net.Name},
			NetworkAliases: map[string][]string{net.Name: {"mockgoogle"}},
			WaitingFor:     wait.ForHTTP("/healthz").WithPort("8080/tcp").WithStartupTimeout(2 * time.Minute),
		},
		Started: true,
	})
	track(ctx, t, "mockgoogle", mock)
	require.NoError(t, err, "mockgoogle")
	mockBase := mappedHTTP(ctx, t, mock, "8080")

	env := redirectTestEnv(cliClientID + ":http://127.0.0.1/callback," + deviceClientID + ":")
	// A fast reaper and a refresh session that ends within the test; the
	// rate limits are the shipped defaults.
	env["STATE_REAPER_INTERVAL"] = "2s"
	env["LOG_LEVEL"] = "debug"
	env["OIDC_ACCESS_TOKEN_TTL"] = "2s"
	env["OIDC_REFRESH_TOKEN_TTL"] = "4s"
	env["OIDC_REFRESH_MAX_LIFETIME"] = "8s"
	tg := &restartableTempogate{ctx: ctx, owner: t, root: root, netName: net.Name}
	tg.start(t, env, true)
	httpc := &http.Client{
		Timeout:       15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	t.Run("oversized parameters are refused and write nothing", func(t *testing.T) {
		before := stateBytes(ctx, t, tg.serve)

		sum := sha256.Sum256([]byte(attackerVerifier))
		authorize := func(param, value string) *http.Response {
			q := url.Values{
				"response_type":         {"code"},
				"client_id":             {cliClientID},
				"redirect_uri":          {refreshCLICallback},
				"scope":                 {"openid email"},
				"state":                 {"client-state"},
				"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
				"code_challenge_method": {"S256"},
			}
			q.Set(param, value)
			resp, err := httpc.Get(tg.base + "/authorize?" + q.Encode())
			require.NoError(t, err)
			return resp
		}
		big := strings.Repeat("A", 8<<10)
		for _, param := range []string{"state", "nonce", "scope"} {
			for range 4 {
				value := big
				if param == "scope" {
					value = "openid " + big
				}
				resp := authorize(param, value)
				require.Equalf(t, http.StatusBadRequest, resp.StatusCode, "/authorize with an 8 KiB %s", param)
				require.Equal(t, "invalid_request", decodeOAuthErrorCode(t, resp))
				require.Empty(t, resp.Header.Get("Location"))
			}
		}
		for range 3 {
			resp, err := httpc.PostForm(tg.base+"/device_authorization", url.Values{
				"client_id": {deviceClientID},
				"scope":     {"openid " + strings.Repeat("A", 200<<10)},
			})
			require.NoError(t, err)
			require.Equal(t, http.StatusBadRequest, resp.StatusCode, "/device_authorization with a 200 KiB scope")
			require.Equal(t, "invalid_request", decodeOAuthErrorCode(t, resp))
		}

		// 12 x 8 KiB + 3 x 200 KiB would have been stored before the fix.
		after := stateBytes(ctx, t, tg.serve)
		assert.LessOrEqualf(t, after-before, int64(16<<10),
			"the state files grew from %d to %d bytes", before, after)
	})

	t.Run("expired rows are reaped, refresh tombstones only with their family", func(t *testing.T) {
		r := &refresher{t: t, base: tg.base, httpc: &http.Client{Timeout: 15 * time.Second}}
		// A code nobody redeems (expires after a minute) and a session
		// that rotated once: a consumed tombstone plus its live successor.
		r.code(mockBase, cliClientID, refreshCLICallback)
		signedIn := time.Now()
		rt := r.cliRefreshToken(mockBase)
		rt2 := r.refreshOK(r.post(url.Values{"client_id": {cliClientID}}, rt, "", ""), cliClientID)
		require.NotEmpty(t, rt2)

		counts := stateRowCounts(ctx, t, tg.serve)
		// The redeemed code stays as a tombstone until it expires, so a
		// replay can revoke what it issued.
		require.Equal(t, 2, counts["auth_codes"], "the unredeemed code and the redeemed code's tombstone are stored")
		require.Equal(t, 2, counts["refresh_tokens"], "tombstone + live token")

		// Several reaper ticks later, still inside the 8 s absolute
		// lifetime: the family is intact, so a replay of the rotated
		// token would still be caught.
		time.Sleep(time.Until(signedIn.Add(6 * time.Second)))
		require.Equal(t, 2, stateRowCounts(ctx, t, tg.serve)["refresh_tokens"], "the family is kept until its absolute expiry")

		deadline := time.Now().Add(2 * time.Minute)
		for {
			c := stateRowCounts(ctx, t, tg.serve)
			if c["refresh_tokens"] == 0 && c["auth_codes"] == 0 {
				break
			}
			require.Truef(t, time.Now().Before(deadline),
				"the ended family and the expired code are deleted within 2 minutes; still have %v", c)
			time.Sleep(3 * time.Second)
		}
		tg.waitForLogs(t, "reaped expired state")
	})

	t.Run("a burst past the per-address limit gets 429", func(t *testing.T) {
		// /device_authorization allows 10 per minute per address by
		// default; the oversized requests above spent 3 of them.
		var resp *http.Response
		for i := range 11 {
			resp, err = httpc.PostForm(tg.base+"/device_authorization", url.Values{
				"client_id": {deviceClientID},
				"scope":     {"openid"},
			})
			require.NoError(t, err)
			if resp.StatusCode == http.StatusTooManyRequests {
				require.GreaterOrEqualf(t, i, 6, "429 only once the budget is spent (request %d)", i+1)
				break
			}
			require.Equal(t, http.StatusOK, resp.StatusCode)
			_ = resp.Body.Close()
		}
		require.Equal(t, http.StatusTooManyRequests, resp.StatusCode, "the burst is throttled")
		assert.Equal(t, "6", resp.Header.Get("Retry-After"))
		b, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		_ = resp.Body.Close()
		var body struct {
			Error string `json:"error"`
		}
		require.NoErrorf(t, json.Unmarshal(b, &body), "429 body: %s", b)
		assert.Equal(t, "temporarily_unavailable", body.Error)

		// Each endpoint has its own budget.
		r := &refresher{t: t, base: tg.base, httpc: &http.Client{Timeout: 15 * time.Second}}
		r.refreshOK(r.post(url.Values{"client_id": {cliClientID}}, r.cliRefreshToken(mockBase), "", ""), cliClientID)
	})
}

// stateBytes is the size of the database and its WAL inside the container:
// every write lands in one of the two.
func stateBytes(ctx context.Context, t *testing.T, c testcontainers.Container) int64 {
	t.Helper()
	files := copyDirOut(ctx, t, c, "/state")
	return int64(len(files["state.db"].data) + len(files["state.db-wal"].data))
}

// stateRowCounts copies the state files out of the running container and
// counts rows per table in the copy. The copy is not atomic, so a write
// landing mid-copy can tear it; that attempt is retried.
func stateRowCounts(ctx context.Context, t *testing.T, c testcontainers.Container) map[string]int {
	t.Helper()
	var (
		counts map[string]int
		err    error
	)
	for range 5 {
		if counts, err = tryStateRowCounts(ctx, t.TempDir(), c); err == nil {
			return counts
		}
		time.Sleep(500 * time.Millisecond)
	}
	require.NoError(t, err, "count rows in a copy of the state database")
	return nil
}

func tryStateRowCounts(ctx context.Context, dir string, c testcontainers.Container) (map[string]int, error) {
	out, err := exec.CommandContext(ctx, "docker", "cp", c.GetContainerID()+":/state", "-").Output()
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(bytes.NewReader(out))
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		name := path.Base(h.Name)
		if !strings.HasPrefix(name, "state.db") {
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "state.db"))
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()
	counts := map[string]int{}
	for _, table := range []string{"auth_requests", "auth_codes", "device_codes", "browser_sessions", "refresh_tokens"} {
		var n int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM `+table).Scan(&n); err != nil {
			return nil, err
		}
		counts[table] = n
	}
	return counts, nil
}
