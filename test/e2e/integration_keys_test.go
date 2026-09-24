//go:build e2e

// Acceptance proof for the integration-keys story: a backend caller mints a
// long-lived JWT against tempogate's admin API (on a *separate* listener from
// the public OIDC surface), authenticates a real gRPC call to a real
// temporal-frontend whose default authorizer is JWKS-backed by tempogate, then
// revokes the key and observes the dual revocation contract — *immediate*
// rejection on tempogate-mediated verify paths (DELETE hydrates the verifier
// cache synchronously; the 30s cache TTL is the cold-start worst case) and
// *no* effect on the Temporal frontend for the remainder of the token's life
// (Temporal's default ClaimMapper has no denylist concept, so until exp fires
// the token keeps authorizing cluster APIs).
//
// Listener isolation is verified structurally: the same POST that succeeds on
// the admin port returns 404 on the public port — a property of *binding* (two
// http.Server instances, two muxes, no /admin/* registrar on the public one),
// not of a middleware decision.
//
// "JTI is in the denylist store" is asserted three ways in increasing
// independence:
//   - GET /admin/keys/{id} reports `revoked_at != null` (the admin contract);
//   - GET /userinfo with the revoked Bearer returns 401 within 30s (the
//     verifier-cache + denylist read path the production /userinfo handler
//     uses);
//   - the SQLite state file copied off the container shows the jti in the
//     `jti_denylist` table directly (structural, independent of any HTTP
//     surface). The first two are admin-API observations; the third is the
//     "separate assertion" the issue calls for.
package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcnetwork "github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.temporal.io/api/workflowservice/v1"
	"google.golang.org/grpc/metadata"

	"github.com/onhotpath/tempogate/state/sqlite"
)

// adminCreateBody mirrors admin.createBody (kept here as a black-box JSON
// shape so a drift in the handler is caught as a 400 from this test, not as a
// missing-import error).
type adminCreateBody struct {
	Namespace string     `json:"namespace"`
	Role      string     `json:"role"`
	Owner     string     `json:"owner"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

type adminCreateResp struct {
	ID        string     `json:"id"`
	JWT       string     `json:"jwt"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

type adminKeyView struct {
	ID        string     `json:"id"`
	Namespace string     `json:"namespace"`
	Role      string     `json:"role"`
	Owner     string     `json:"owner"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

type integrationKeysStack struct {
	tempogate    testcontainers.Container
	publicURL    string // http://host:port for the public listener (OIDC + /userinfo + /healthz)
	adminURL     string // http://host:port for the admin listener (/admin/*)
	frontendAddr string // host:port for the gRPC temporal-frontend
}

func TestAdminKeyMintAndRevoke(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e: skipped in -short")
	}
	ctx := context.Background()
	st := setupIntegrationKeysStack(ctx, t)

	// Listener isolation: the admin route MUST be unreachable from the public
	// listener. This is a property of how the two http.Servers are wired (no
	// /admin/* handler on the public mux at all), so a 404 here proves the
	// invariant; any middleware-based "allowlist" would fail this check the
	// moment it was bypassed.
	probe, err := http.Post(st.publicURL+"/admin/keys",
		"application/json", strings.NewReader(`{}`))
	require.NoError(t, err)
	require.NoError(t, probe.Body.Close())
	require.Equal(t, http.StatusNotFound, probe.StatusCode,
		"public listener must not expose /admin/* — admin API lives on its own listener")

	// --- mint via the admin listener ---
	created := mintIntegrationKey(t, st.adminURL, adminCreateBody{
		Namespace: "temporal-system",
		Role:      "admin",
		Owner:     "e2e-integration",
	})
	require.NotEmpty(t, created.ID)
	require.NotEmpty(t, created.JWT)

	// Parse the JWT once to lift its jti — needed for the SQLite-side
	// denylist probe further down. ParseInsecure is correct: the assertion
	// is on the claim contents, not on the signature (the gRPC call below
	// is the signature-validity proof).
	parsed, err := jwt.ParseInsecure([]byte(created.JWT))
	require.NoError(t, err, "minted token must be a parseable JWT")
	mintedJTI, ok := parsed.JwtID()
	require.True(t, ok, "every tempogate-minted token carries a jti")
	require.NotEmpty(t, mintedJTI)
	perms, ok := parsed.Field("permissions")
	require.True(t, ok)
	require.Equal(t, []any{"temporal-system:admin"}, perms,
		"namespace+role must concatenate into the permissions claim Temporal's default ClaimMapper consumes")

	// --- the JWT authenticates a real gRPC call against temporal-frontend ---
	client, conn := dialFrontend(t, st.frontendAddr)
	defer func() { _ = conn.Close() }()

	authed := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+created.JWT)
	resp, err := client.ListNamespaces(authed, &workflowservice.ListNamespacesRequest{PageSize: 10})
	require.NoError(t, err, "minted integration JWT must pass Temporal's JWKS-backed authorizer")
	require.NotEmpty(t, resp.GetNamespaces(), "admin-scoped token should see namespaces")

	// Pre-revoke: the same JWT also passes the tempogate-internal Verifier on
	// /userinfo — confirms the denylist check is wired and is *not* falsely
	// rejecting before the revoke.
	require.Equal(t, http.StatusOK, userinfoStatus(t, st.publicURL, created.JWT),
		"pre-revoke: /userinfo must accept the freshly-minted JWT")

	// --- revoke via the admin listener ---
	revokeIntegrationKey(t, st.adminURL, created.ID)

	// Acceptance #1 — admin contract: GET reflects the revoke. Because
	// MarkIntegrationKeyRevoked writes the integration_keys row update and
	// the jti_denylist insert in the *same* transaction (state/sqlite/
	// integration_keys.go), `revoked_at != null` on the GET response is also
	// the admin-API confirmation that the jti is now in the denylist store.
	got := fetchIntegrationKey(t, st.adminURL, created.ID)
	require.NotNil(t, got.RevokedAt, "GET /admin/keys/{id} must report revoked_at after DELETE")

	// Acceptance #2 — tempogate-side verify: /userinfo rejects within 30s.
	// In practice DELETE's synchronous denylist hydrate makes the very next
	// call fail; the 30s bound is the cache TTL worst case if the hydrate
	// path were ever silently removed. Eventually with a tight poll keeps the
	// fast path fast and surfaces a stuck verifier within a deterministic
	// window.
	require.Eventually(t, func() bool {
		return userinfoStatus(t, st.publicURL, created.JWT) == http.StatusUnauthorized
	}, 30*time.Second, 250*time.Millisecond,
		"tempogate-mediated verify must reject the revoked JWT within the denylist cache TTL")

	// Acceptance #3 — *documented* Temporal-side trade-off. The default
	// ClaimMapper has no denylist hook, so until the JWT's `exp` fires it
	// keeps authorizing Temporal cluster APIs. This is not a bug to fix in
	// this story — moving integration keys to opaque tokens (instant revoke
	// end-to-end) is tracked as future product debt. The assertion below
	// codifies the trade-off so a future change that *did* close it would
	// fail this test loudly and force an intentional update.
	resp, err = client.ListNamespaces(authed, &workflowservice.ListNamespacesRequest{PageSize: 10})
	require.NoError(t, err,
		"documented trade-off: Temporal frontend still accepts a JWKS-valid JWT post-revoke "+
			"(default ClaimMapper has no denylist concept). Closing this requires opaque tokens.")
	require.NotEmpty(t, resp.GetNamespaces())

	// Acceptance #4 — separate, *structural* proof that the jti landed in the
	// persistent store. Independent of any HTTP surface: copy the SQLite
	// state file off the container and read jti_denylist directly with the
	// same driver tempogate uses. Settles "did the row actually get written"
	// without trusting either the admin API or the verifier cache.
	assertJTIInDenylistStore(ctx, t, st.tempogate, mintedJTI)
}

// mintIntegrationKey POSTs to /admin/keys on the admin listener and returns
// the decoded response. The Content-Type round-trip is what Huma's negotiation
// requires, so a wiring slip (e.g. admin handler on the wrong mux) surfaces as
// a clear test failure here rather than as an opaque non-201.
func mintIntegrationKey(t *testing.T, adminURL string, body adminCreateBody) adminCreateResp {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	resp, err := http.Post(adminURL+"/admin/keys",
		"application/json", strings.NewReader(string(raw)))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	require.Equalf(t, http.StatusCreated, resp.StatusCode,
		"POST /admin/keys: %s", b)
	var out adminCreateResp
	require.NoError(t, json.Unmarshal(b, &out))
	return out
}

func fetchIntegrationKey(t *testing.T, adminURL, id string) adminKeyView {
	t.Helper()
	resp, err := http.Get(adminURL + "/admin/keys/" + id)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	require.Equalf(t, http.StatusOK, resp.StatusCode,
		"GET /admin/keys/%s: %s", id, b)
	var out adminKeyView
	require.NoError(t, json.Unmarshal(b, &out))
	return out
}

func revokeIntegrationKey(t *testing.T, adminURL, id string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodDelete, adminURL+"/admin/keys/"+id, http.NoBody)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusNoContent, resp.StatusCode,
		"DELETE /admin/keys/{id} must answer 204")
}

// userinfoStatus exercises the public listener's Verifier-backed /userinfo
// endpoint with the given Bearer and returns the response status. This is the
// production code path that consults the denylist cache, so its rejection
// before vs. after DELETE is a faithful proxy for "the verifier sees the jti
// as revoked".
func userinfoStatus(t *testing.T, publicURL, raw string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, publicURL+"/userinfo", http.NoBody)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+raw)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// assertJTIInDenylistStore copies the SQLite state file (and its WAL/SHM
// siblings, so committed-but-not-checkpointed pages are visible) off the
// running tempogate container and uses the same pure-Go sqlite driver
// tempogate itself uses to read jti_denylist. Avoids any dependency on a
// distroless container shipping a sqlite3 CLI; avoids a debug HTTP surface
// that would pollute the production listener.
func assertJTIInDenylistStore(ctx context.Context, t *testing.T, c testcontainers.Container, jti string) {
	t.Helper()
	dir := t.TempDir()
	local := filepath.Join(dir, "state.db")

	for _, suffix := range []string{"", "-wal", "-shm"} {
		// -wal and -shm only exist when the writer has held the file open,
		// which is the case here; tolerate their absence regardless so the
		// assertion does not become brittle to SQLite checkpointing on shutdown.
		err := copyFromContainerTo(ctx, c, "/state/state.db"+suffix, local+suffix)
		if suffix == "" {
			require.NoErrorf(t, err, "copy /state/state.db off container")
		}
	}

	store, err := sqlite.New(sqlite.WithPath(local), sqlite.WithBusyTimeout(2*time.Second))
	require.NoError(t, err, "open copied state.db with the same pure-Go driver")
	t.Cleanup(func() { _ = store.Close() })

	revoked, err := store.IsRevoked(ctx, jti)
	require.NoError(t, err)
	require.True(t, revoked,
		"jti %q must be present in the persistent jti_denylist (structural acceptance criterion)", jti)
}

func copyFromContainerTo(ctx context.Context, c testcontainers.Container, remote, local string) error {
	rc, err := c.CopyFileFromContainer(ctx, remote)
	if err != nil {
		return fmt.Errorf("copy %s: %w", remote, err)
	}
	defer func() { _ = rc.Close() }()
	b, err := io.ReadAll(rc)
	if err != nil {
		return fmt.Errorf("read %s: %w", remote, err)
	}
	// 0o600: same posture as ~/.tempogate/token.json — the state file holds
	// signing-key material and integration-key rows.
	return os.WriteFile(local, b, 0o600)
}

// ---------- stack bring-up ----------

func setupIntegrationKeysStack(ctx context.Context, t *testing.T) *integrationKeysStack {
	t.Helper()
	root := repoRoot(t)

	net, err := tcnetwork.New(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = net.Remove(ctx) })
	netName := net.Name
	alias := func(name string) map[string][]string { return map[string][]string{netName: {name}} }

	// OIDC config is required for fx graph construction (the OIDC surface is
	// always wired even when this test never drives an SSO flow). The Google
	// endpoints point at non-routable mock hostnames intentionally: this test
	// must not depend on a mock-Google container coming up, and the OIDC
	// surface only contacts Google during /callback/google, which we never
	// invoke.
	tgEnv := map[string]string{
		"HTTP_LISTENER":              "0.0.0.0:8000",
		"ADMIN_LISTENER":             "0.0.0.0:8081",
		"STATE_SQLITE_PATH":          "/state/state.db",
		"OIDC_ISSUER":                tempogateIssuer,
		"OIDC_CLIENTS":               "noop:https://noop.invalid/cb",
		"OIDC_ALLOWED_DOMAINS":       "example.com",
		"OIDC_GOOGLE_CLIENT_ID":      "tempogate-upstream",
		"OIDC_GOOGLE_CLIENT_SECRET":  "tempogate-upstream-secret",
		"OIDC_GOOGLE_AUTH_ENDPOINT":  "http://unused.invalid/auth",
		"OIDC_GOOGLE_TOKEN_ENDPOINT": "http://unused.invalid/token",
		"OIDC_GOOGLE_ISSUER_URL":     "http://unused.invalid",
	}
	addDeviceUIServerEnv(tgEnv, tempogateIssuer)
	stateVol := fmt.Sprintf("tempogate-intkeys-e2e-state-%d", time.Now().UnixNano())
	tgImg, tgFrom := builtImageSource("E2E_TEMPOGATE_IMAGE", "Dockerfile", root)

	migrate, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:          tgImg,
			FromDockerfile: tgFrom,
			Cmd:            []string{"migrate"},
			Env:            tgEnv,
			User:           "0:0",
			Mounts:         testcontainers.Mounts(testcontainers.VolumeMount(stateVol, "/state")),
			WaitingFor:     wait.ForExit().WithExitTimeout(2 * time.Minute),
		},
		Started: true,
	})
	require.NoError(t, err, "tempogate migrate")
	track(ctx, t, "tempogate-migrate", migrate)

	// Two exposed ports prove structurally that the admin listener is a
	// separate bind: a single http.Server cannot answer on two ports.
	tempogate, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:          tgImg,
			FromDockerfile: tgFrom,
			Cmd:            []string{"serve"},
			Env:            tgEnv,
			User:           "0:0",
			Mounts:         testcontainers.Mounts(testcontainers.VolumeMount(stateVol, "/state")),
			ExposedPorts:   []string{"8000/tcp", "8081/tcp"},
			Networks:       []string{netName},
			NetworkAliases: alias("tempogate"),
			WaitingFor: wait.ForAll(
				wait.ForHTTP("/readyz").WithPort("8000/tcp"),
				wait.ForHTTP("/admin/healthz").WithPort("8081/tcp"),
			).WithStartupTimeoutDefault(2 * time.Minute),
		},
		Started: true,
	})
	require.NoError(t, err, "tempogate serve")
	track(ctx, t, "tempogate", tempogate)

	pg, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image: postgresImage,
			Env: map[string]string{
				"POSTGRES_USER": "temporal", "POSTGRES_PASSWORD": "temporal", "POSTGRES_DB": "temporal",
			},
			Networks:       []string{netName},
			NetworkAliases: alias("db"),
			WaitingFor: wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).WithStartupTimeout(2 * time.Minute),
		},
		Started: true,
	})
	require.NoError(t, err, "postgres")
	track(ctx, t, "postgres", pg)

	temporal, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image: temporalImage,
			Env: map[string]string{
				"DB": "postgres12", "DB_PORT": "5432",
				"POSTGRES_USER": "temporal", "POSTGRES_PWD": "temporal",
				"POSTGRES_SEEDS": "db", "DBNAME": "temporal",
				"BIND_ON_IP":                      "0.0.0.0",
				"USE_INTERNAL_FRONTEND":           "true",
				"SKIP_DEFAULT_NAMESPACE_CREATION": "true",
				"SERVICES":                        "frontend:internal-frontend:history:matching:worker",
				"TEMPORAL_JWT_KEY_SOURCE1":        tempogateIssuer + "/.well-known/jwks.json",
				"TEMPORAL_JWT_KEY_REFRESH":        "10s",
				"TEMPORAL_AUTH_AUTHORIZER":        "default",
				"TEMPORAL_AUTH_CLAIM_MAPPER":      "default",
			},
			ExposedPorts:   []string{"7233/tcp"},
			Networks:       []string{netName},
			NetworkAliases: alias("temporal"),
			WaitingFor:     wait.ForLog("Temporal server started").WithStartupTimeout(4 * time.Minute),
		},
		Started: true,
	})
	require.NoError(t, err, "temporal")
	track(ctx, t, "temporal", temporal)

	return &integrationKeysStack{
		tempogate:    tempogate,
		publicURL:    mappedHTTP(ctx, t, tempogate, "8000"),
		adminURL:     mappedHTTP(ctx, t, tempogate, "8081"),
		frontendAddr: mappedAddr(ctx, t, temporal, "7233"),
	}
}
