//go:build e2e

// Acceptance proof for secrets at rest (M6) against the real tempogate
// image: after a CLI code-flow login, a refresh and a device login, the
// state directory and its SQLite files (database, -wal, -shm) are owner-only,
// and none of the bearer secrets tempogate issued (refresh tokens, auth codes,
// device codes, the verification-page session id) appear anywhere in their
// bytes; only their SHA-256 does. With KEYS_ENCRYPTION_KEY set the signing
// key is not stored in clear, yet the tokens it signs still authenticate
// against Temporal. Before the fix the files were 0644 and every one of
// those values, and the PEM, was readable in the copied database.
//
// A second test runs the image the way the Helm chart does (uid 65532 on a
// group-owned, setgid fsGroup volume) across a restart, with the kubelet's
// group-permission fix-up in between, to prove the tighter modes do not lock
// tempogate out of its own volume.
package e2e

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcnetwork "github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.temporal.io/api/workflowservice/v1"
	"google.golang.org/grpc/metadata"

	"github.com/onhotpath/tempogate/oidc"
)

// e2eKEK is a fixed, public 32-byte test key (base64 of
// "kek-for-the-e2e-suite-only-0001!"), stable so a run is reproducible.
const e2eKEK = "a2VrLWZvci10aGUtZTJlLXN1aXRlLW9ubHktMDAwMSE="

func TestSecretsAtRest(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e: skipped in -short")
	}
	t.Parallel()
	ctx := context.Background()
	st := setupCLIStack(ctx, t, withImageUser(), withTempogateEnv(map[string]string{"KEYS_ENCRYPTION_KEY": e2eKEK}))
	(&stack{mockBaseURL: st.mockBaseURL}).setIdentity(t, allowedEmail, true)

	secrets := map[string]string{}
	r := &refresher{t: t, base: st.tempogateBaseURL, httpc: &http.Client{Timeout: 15 * time.Second}}

	// --- CLI code-flow login, then a refresh (the first token becomes a
	// consumed tombstone, the second stays live).
	code := r.code(st.mockBaseURL, cliClientID, refreshCLICallback)
	rt1 := r.refreshOK(r.postToken(url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {cliClientID},
		"code":          {code},
		"redirect_uri":  {refreshCLICallback},
		"code_verifier": {attackerVerifier},
	}, "", ""), cliClientID)
	resp := r.post(url.Values{"client_id": {cliClientID}}, rt1, "", "")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var refreshed struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&refreshed))
	_ = resp.Body.Close()
	secrets["consumed auth code"] = code
	secrets["rotated refresh token"] = rt1
	secrets["live refresh token"] = refreshed.RefreshToken
	secrets["live auth code"] = r.code(st.mockBaseURL, cliClientID, refreshCLICallback)

	// --- device login: approve in the verification UI, then redeem.
	deviceCode, userCode := startDeviceAuthorization(t, st.tempogateBaseURL)
	cookie := st.driveDeviceDecision(ctx, t, userCode, "approve")
	sid, err := base64.RawURLEncoding.DecodeString(strings.SplitN(cookie.Value, ".", 2)[0])
	require.NoError(t, err, "the session cookie is base64url(sid).mac")
	resp = r.postToken(url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"client_id":   {deviceClientID},
		"device_code": {deviceCode},
	}, "", "")
	require.Equal(t, http.StatusOK, resp.StatusCode, "device code redeems after approval")
	_ = resp.Body.Close()
	secrets["consumed device code"] = deviceCode
	secrets["browser session id"] = string(sid)
	secrets["live device code"], _ = startDeviceAuthorization(t, st.tempogateBaseURL)

	// --- tokens signed with the encrypted key still authenticate.
	client, conn := dialFrontend(t, st.frontendAddr)
	defer func() { _ = conn.Close() }()
	authed := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+refreshed.AccessToken)
	_, err = client.ListNamespaces(authed, &workflowservice.ListNamespacesRequest{PageSize: 10})
	require.NoError(t, err, "Temporal accepts a token signed with the KEK-encrypted key")

	// --- the state directory, copied out of the running container. Checks
	// are non-fatal so one run reports every exposure.
	files := copyDirOut(ctx, t, st.tempogate, "/var/lib/tempogate")
	assert.Equal(t, "700", modeOf(files["."]), "state directory is owner-only")
	var all []byte
	for _, name := range []string{"state.db", "state.db-wal", "state.db-shm"} {
		f, ok := files[name]
		require.Truef(t, ok, "%s exists", name)
		assert.Equalf(t, "600", modeOf(f), "%s is owner-only", name)
		assert.Equalf(t, 65532, f.uid, "%s is owned by the image's nonroot user", name)
		all = append(all, f.data...)
	}
	for name, v := range secrets {
		require.NotEmpty(t, v, name)
		assert.Falsef(t, bytes.Contains(all, []byte(v)), "raw %s found in the state files", name)
	}
	liveHash := sha256.Sum256([]byte(secrets["live refresh token"]))
	assert.True(t, bytes.Contains(all, []byte(hex.EncodeToString(liveHash[:]))),
		"the live refresh token's hash is there: the scan read the real data")
	assert.False(t, bytes.Contains(all, []byte("PRIVATE KEY")), "the signing key is not stored in clear")
	assert.True(t, bytes.Contains(all, []byte("tempogate-kek:v1:")), "the signing key is stored encrypted")
}

// TestStateVolumeUnderFSGroup runs migrate + serve as the chart does: uid
// and gid 65532 on a root-owned, group-65532, setgid volume. Between two
// boots it re-applies the group read/write bits the kubelet sets on fsGroup
// volumes; tempogate must still boot and put its files back to 0600.
func TestStateVolumeUnderFSGroup(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e: skipped in -short")
	}
	t.Parallel()
	ctx := context.Background()
	root := repoRoot(t)
	net, err := tcnetwork.New(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = net.Remove(ctx) })

	vol := "tempogate-fsgroup-e2e-state-" + strings.ReplaceAll(time.Now().Format("150405.000000000"), ".", "")
	t.Cleanup(func() { _ = exec.Command("docker", "volume", "rm", "-f", vol).Run() })
	mounts := testcontainers.Mounts(testcontainers.VolumeMount(vol, "/state"))
	asRoot := func(name, script string) {
		c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Image: postgresImage, Entrypoint: []string{"sh", "-c", script}, User: "0:0", Mounts: mounts,
				WaitingFor: wait.ForExit().WithExitTimeout(time.Minute),
			},
			Started: true,
		})
		require.NoError(t, err, name)
		track(ctx, t, name, c)
	}
	asRoot("fsgroup-volume", "chown 0:65532 /state && chmod 2770 /state")

	env := redirectTestEnv(cliClientID + ":http://127.0.0.1/callback")
	tgImg, tgFrom := builtImageSource("E2E_TEMPOGATE_IMAGE", "Dockerfile", root)
	run := func(name string, cmd []string, until wait.Strategy) testcontainers.Container {
		c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Image: tgImg, FromDockerfile: tgFrom, Cmd: cmd, Env: env, User: "65532:65532", Mounts: mounts,
				ExposedPorts: []string{"8000/tcp"}, Networks: []string{net.Name}, WaitingFor: until,
			},
			Started: true,
		})
		require.NoError(t, err, name)
		track(ctx, t, name, c)
		return c
	}
	ready := wait.ForHTTP("/readyz").WithPort("8000/tcp").WithStartupTimeout(2 * time.Minute)

	run("fsgroup-migrate", []string{"migrate"}, wait.ForExit().WithExitTimeout(2*time.Minute))
	first := run("fsgroup-serve-1", []string{"serve"}, ready)
	requireOwnerOnlyDB(ctx, t, first)
	require.NoError(t, first.Terminate(ctx))

	asRoot("fsgroup-kubelet-fixup", "chmod g+rw /state/state.db*")
	second := run("fsgroup-serve-2", []string{"serve"}, ready)
	requireOwnerOnlyDB(ctx, t, second)
	files := copyDirOut(ctx, t, second, "/state")
	assert.Equal(t, "2770", modeOf(files["."]), "a pre-existing volume root is left as the operator set it")
}

func requireOwnerOnlyDB(ctx context.Context, t *testing.T, c testcontainers.Container) {
	t.Helper()
	files := copyDirOut(ctx, t, c, "/state")
	for _, name := range []string{"state.db", "state.db-wal", "state.db-shm"} {
		f, ok := files[name]
		require.Truef(t, ok, "%s exists", name)
		assert.Equalf(t, "600", modeOf(f), "%s is owner-only", name)
		assert.Equalf(t, 65532, f.uid, "%s owner", name)
	}
}

func startDeviceAuthorization(t *testing.T, base string) (deviceCode, userCode string) {
	t.Helper()
	resp, err := http.PostForm(base+oidc.DeviceAuthorizationPath,
		url.Values{"client_id": {deviceClientID}, "scope": {"openid email"}})
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body struct {
		DeviceCode string `json:"device_code"`
		UserCode   string `json:"user_code"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	return body.DeviceCode, body.UserCode
}

// modeOf renders permission and setgid bits in octal, the way ls and chmod
// spell them, so a failure reads "644" rather than a decimal.
func modeOf(f copiedFile) string { return strconv.FormatInt(f.mode&0o7777, 8) }

type copiedFile struct {
	mode int64
	uid  int
	data []byte
}

// copyDirOut reads dir out of the container as the tar `docker cp` streams,
// which carries each entry's mode and owner (testcontainers' copy helpers
// drop both). Keys are paths relative to dir; "." is dir itself.
func copyDirOut(ctx context.Context, t *testing.T, c testcontainers.Container, dir string) map[string]copiedFile {
	t.Helper()
	out, err := exec.CommandContext(ctx, "docker", "cp", c.GetContainerID()+":"+dir, "-").Output()
	require.NoError(t, err, "docker cp %s", dir)
	files := map[string]copiedFile{}
	tr := tar.NewReader(bytes.NewReader(out))
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		data, err := io.ReadAll(tr)
		require.NoError(t, err)
		rel := strings.TrimPrefix(strings.TrimPrefix(h.Name, path.Base(dir)), "/")
		if rel == "" {
			rel = "."
		}
		files[rel] = copiedFile{mode: h.Mode, uid: h.Uid, data: data}
	}
	return files
}
