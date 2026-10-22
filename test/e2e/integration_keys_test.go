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
// the token keeps authorizing cluster APIs). Every key carries an exp capped
// by ADMIN_KEYS_MAX_TTL; retiring the signing key is the hard kill switch
// (TestSigningKeyRotationAndRetirement).
//
// Listener isolation is verified structurally: the same POST that succeeds on
// the admin port returns 404 on the public port — a property of *binding* (two
// http.Server instances, two muxes, no /admin/* registrar on the public one),
// not of a middleware decision.
//
// The admin API itself is authenticated: every /admin/* route except
// /admin/healthz needs the bearer token whose SHA-256 is in ADMIN_TOKEN_SHA256,
// a request whose Host is not in ADMIN_ALLOWED_HOSTS is refused with 421
// before auth runs (DNS-rebinding defence), and temporal-system grants are
// refused unless ADMIN_ALLOW_SYSTEM_GRANTS=true.
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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
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
	t.Parallel()
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

	// --- the admin listener refuses unauthenticated and rebinding callers ---
	systemGrant := `{"namespace":"temporal-system","role":"admin","owner":"e2e-anon"}`
	status, body := adminRequest(t, http.MethodPost, st.adminURL+"/admin/keys", "", "", systemGrant)
	require.Equalf(t, http.StatusUnauthorized, status, "anonymous mint must be refused: %s", body)
	status, body = adminRequest(t, http.MethodPost, st.adminURL+"/admin/keys", "", "not-the-admin-token", systemGrant)
	require.Equalf(t, http.StatusUnauthorized, status, "wrong-token mint must be refused: %s", body)
	status, body = adminRequest(t, http.MethodGet, st.adminURL+"/admin/keys", "", "", "")
	require.Equalf(t, http.StatusUnauthorized, status, "anonymous list must be refused: %s", body)
	status, body = adminRequest(t, http.MethodPost, st.adminURL+"/admin/keys", "evil.example", e2eAdminToken, systemGrant)
	require.Equalf(t, http.StatusMisdirectedRequest, status,
		"a DNS-rebinding Host must be refused even with a valid token: %s", body)
	status, _ = adminRequest(t, http.MethodGet, st.adminURL+"/admin/healthz", "evil.example", "", "")
	require.Equal(t, http.StatusOK, status, "the liveness probe stays open")

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
	aud, _ := parsed.Audience()
	require.Equal(t, []string{temporalAudience}, aud, "an integration key is an access token for the Temporal audience")

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

// TestAdminRefusesSystemGrantByDefault runs tempogate with the shipped default
// ADMIN_ALLOW_SYSTEM_GRANTS=false: an authenticated caller can mint
// namespace-scoped keys but not a cluster-wide temporal-system grant.
func TestAdminRefusesSystemGrantByDefault(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e: skipped in -short")
	}
	t.Parallel()
	ctx := context.Background()
	net, err := tcnetwork.New(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = net.Remove(ctx) })
	tg := startIntegrationKeysTempogate(ctx, t, net.Name, false)
	adminURL := mappedHTTP(ctx, t, tg, "8081")

	status, body := adminRequest(t, http.MethodPost, adminURL+"/admin/keys", "", e2eAdminToken,
		`{"namespace":"temporal-system","role":"admin","owner":"e2e-system"}`)
	require.Equalf(t, http.StatusForbidden, status, "temporal-system grant must be refused by default: %s", body)
	require.NotContains(t, string(body), `"jwt"`)

	created := mintIntegrationKey(t, adminURL, adminCreateBody{
		Namespace: "payments",
		Role:      "admin",
		Owner:     "e2e-scoped",
	})
	require.NotEmpty(t, created.JWT, "namespace-scoped grants stay available without the flag")
}

// e2eAdminToken is the admin bearer token every e2e tempogate accepts; only
// its SHA-256 reaches the container, as in production.
const e2eAdminToken = "e2e-admin-token-not-a-secret"

func e2eAdminTokenSHA256() string {
	sum := sha256.Sum256([]byte(e2eAdminToken))
	return hex.EncodeToString(sum[:])
}

// addAdminAuthEnv configures the admin guard. The allowlist names the Docker
// daemon host without a port (matches any port) because the mapped host port
// is only known once the container is running, and the test reaches the
// admin listener through that mapping.
func addAdminAuthEnv(ctx context.Context, t *testing.T, env map[string]string, allowSystemGrants bool) {
	t.Helper()
	provider, err := testcontainers.NewDockerProvider()
	require.NoError(t, err)
	defer func() { _ = provider.Close() }()
	host, err := provider.DaemonHost(ctx)
	require.NoError(t, err)
	env["ADMIN_TOKEN_SHA256"] = e2eAdminTokenSHA256()
	env["ADMIN_ALLOWED_HOSTS"] = host
	env["ADMIN_ALLOW_SYSTEM_GRANTS"] = strconv.FormatBool(allowSystemGrants)
}

// adminRequest sends one admin-listener request. Empty host keeps the URL's
// host; empty token sends no Authorization header.
func adminRequest(t *testing.T, method, url, host, token, body string) (int, []byte) {
	t.Helper()
	var rdr io.Reader = http.NoBody
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rdr)
	require.NoError(t, err)
	if host != "" {
		req.Host = host
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, b
}

// mintIntegrationKey POSTs to /admin/keys on the admin listener and returns
// the decoded response. The Content-Type round-trip is what Huma's negotiation
// requires, so a wiring slip (e.g. admin handler on the wrong mux) surfaces as
// a clear test failure here rather than as an opaque non-201.
func mintIntegrationKey(t *testing.T, adminURL string, body adminCreateBody) adminCreateResp {
	t.Helper()
	if body.ExpiresAt == nil {
		// Every key must carry an expiry; tests not about expiry get an hour.
		exp := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
		body.ExpiresAt = &exp
	}
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	status, b := adminRequest(t, http.MethodPost, adminURL+"/admin/keys", "", e2eAdminToken, string(raw))
	require.Equalf(t, http.StatusCreated, status, "POST /admin/keys: %s", b)
	var out adminCreateResp
	require.NoError(t, json.Unmarshal(b, &out))
	return out
}

func fetchIntegrationKey(t *testing.T, adminURL, id string) adminKeyView {
	t.Helper()
	status, b := adminRequest(t, http.MethodGet, adminURL+"/admin/keys/"+id, "", e2eAdminToken, "")
	require.Equalf(t, http.StatusOK, status, "GET /admin/keys/%s: %s", id, b)
	var out adminKeyView
	require.NoError(t, json.Unmarshal(b, &out))
	return out
}

func revokeIntegrationKey(t *testing.T, adminURL, id string) {
	t.Helper()
	status, b := adminRequest(t, http.MethodDelete, adminURL+"/admin/keys/"+id, "", e2eAdminToken, "")
	require.Equalf(t, http.StatusNoContent, status, "DELETE /admin/keys/{id} must answer 204: %s", b)
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

// e2eRetirementGrace is KEYS_RETIREMENT_GRACE for the integration-keys stack.
const e2eRetirementGrace = 20 * time.Second

// e2ePublishDelay is KEYS_PUBLISH_DELAY for the integration-keys stack. It
// must exceed temporal-frontend's JWKS refresh (TEMPORAL_JWT_KEY_REFRESH=10s)
// plus KEYS_RELOAD_INTERVAL (1s), exactly as in production.
const e2ePublishDelay = 20 * time.Second

type signingKeyView struct {
	Kid         string     `json:"kid"`
	CreatedAt   time.Time  `json:"created_at"`
	RetiredAt   *time.Time `json:"retired_at,omitempty"`
	Active      bool       `json:"active"`
	ActivatesAt *time.Time `json:"activates_at,omitempty"`
}

// TestSigningKeyRotationAndRetirement is the acceptance proof for signing-key
// retirement: integration keys must carry a capped expiry, and an operator
// can rotate and retire the signing key of a running tempogate without
// restarting it. A rotated key is published at once but signs only after
// KEYS_PUBLISH_DELAY, so temporal-frontend already holds it when its first
// token arrives. After KEYS_RETIREMENT_GRACE the retired kid leaves
// /.well-known/jwks.json, and once temporal-frontend refreshes its JWKS
// (TEMPORAL_JWT_KEY_REFRESH=10s here) every token signed by that kid stops
// authorizing gRPC calls, exp notwithstanding. That is the hard kill switch the
// jti denylist cannot provide at Temporal.
func TestSigningKeyRotationAndRetirement(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e: skipped in -short")
	}
	t.Parallel()
	ctx := context.Background()
	st := setupIntegrationKeysStack(ctx, t)
	startedAt := containerStartedAt(ctx, t, st.tempogate)

	// --- expires_at is required and capped by ADMIN_KEYS_MAX_TTL (90d) ---
	status, body := adminRequest(t, http.MethodPost, st.adminURL+"/admin/keys", "", e2eAdminToken,
		`{"namespace":"temporal-system","role":"admin","owner":"e2e-forever"}`)
	require.Equalf(t, http.StatusBadRequest, status, "a key without expires_at must be refused: %s", body)
	require.Contains(t, string(body), "expires_at")
	require.NotContains(t, string(body), `"jwt"`)

	tooLong := time.Now().UTC().Add(91 * 24 * time.Hour).Format(time.RFC3339)
	status, body = adminRequest(t, http.MethodPost, st.adminURL+"/admin/keys", "", e2eAdminToken,
		`{"namespace":"temporal-system","role":"admin","owner":"e2e-too-long","expires_at":"`+tooLong+`"}`)
	require.Equalf(t, http.StatusBadRequest, status, "expires_at beyond the max TTL must be refused: %s", body)

	// --- a valid key authenticates a real gRPC call and carries exp ---
	keyA := mintIntegrationKey(t, st.adminURL, adminCreateBody{
		Namespace: "temporal-system", Role: "admin", Owner: "e2e-old-signer",
	})
	parsed, err := jwt.ParseInsecure([]byte(keyA.JWT))
	require.NoError(t, err)
	_, hasExp := parsed.Expiration()
	require.True(t, hasExp, "every integration key must carry exp")
	kidA := tokenKid(t, keyA.JWT)

	client, conn := dialFrontend(t, st.frontendAddr)
	defer func() { _ = conn.Close() }()
	listNamespaces := func(token string) error {
		authed := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
		_, err := client.ListNamespaces(authed, &workflowservice.ListNamespacesRequest{PageSize: 10})
		return err
	}
	require.NoError(t, listNamespaces(keyA.JWT), "key A must pass Temporal's JWKS-backed authorizer")

	before := listSigningKeys(t, st.adminURL)
	require.Len(t, before, 1)
	require.Equal(t, kidA, before[0].Kid)
	require.True(t, before[0].Active)

	// --- refusing to retire the only active key ---
	status, body = retireSigningKey(t, st.adminURL, kidA)
	require.Equalf(t, http.StatusConflict, status, "the only active key cannot be retired: %s", body)

	// --- rotate from another process (the CLI) while serving ---
	out := execTempogate(ctx, t, st.tempogate, "keys", "generate", "--force")
	kidB := regexp.MustCompile(`kid=(\S+)`).FindStringSubmatch(out)
	require.Lenf(t, kidB, 2, "keys generate output: %s", out)
	require.Contains(t, out, "signs from", "the CLI says when the new key starts signing")

	// The serving process publishes the new key on its next reload, but
	// keeps signing with the old one for KEYS_PUBLISH_DELAY: temporal-frontend
	// only knows the kids it fetched on its last JWKS refresh and never
	// refetches on an unknown kid.
	require.Eventually(t, func() bool { return slices.Contains(jwksKids(t, st.publicURL), kidB[1]) },
		15*time.Second, 200*time.Millisecond, "serve must publish the rotated key without a restart")
	pending := mintIntegrationKey(t, st.adminURL, adminCreateBody{
		Namespace: "temporal-system", Role: "admin", Owner: "e2e-pending-signer",
	})
	require.Equal(t, kidA, tokenKid(t, pending.JWT), "the old key signs while the new one is inside KEYS_PUBLISH_DELAY")
	require.NoError(t, listNamespaces(pending.JWT), "a token minted right after the rotation must work at Temporal")

	during := listSigningKeys(t, st.adminURL)
	require.Len(t, during, 2)
	require.True(t, during[0].Active)
	require.False(t, during[1].Active)
	require.NotNil(t, during[1].ActivatesAt, "the pending key shows when it starts signing")

	status, body = retireSigningKey(t, st.adminURL, kidA)
	require.Equalf(t, http.StatusConflict, status,
		"retiring the signer before its replacement is published must be refused: %s", body)
	require.Contains(t, string(body), kidB[1])

	// After the delay the new key signs, and Temporal already has it.
	var keyB adminCreateResp
	require.Eventually(t, func() bool {
		keyB = mintIntegrationKey(t, st.adminURL, adminCreateBody{
			Namespace: "temporal-system", Role: "admin", Owner: "e2e-new-signer",
		})
		return tokenKid(t, keyB.JWT) == kidB[1]
	}, e2ePublishDelay+15*time.Second, 500*time.Millisecond, "the new key must sign once KEYS_PUBLISH_DELAY has passed")
	require.NoError(t, listNamespaces(keyB.JWT),
		"the first token from the new key must authenticate at Temporal at once, with no retry")

	// --- retire the old key from another process (the CLI) ---
	out = execTempogate(ctx, t, st.tempogate, "keys", "retire", "--", kidA)
	require.Contains(t, out, "retired keypair: kid="+kidA)

	// During grace the retired kid is still published, so in-flight tokens
	// keep working while relying parties catch up.
	require.Contains(t, jwksKids(t, st.publicURL), kidA, "a retired kid stays in JWKS during its grace")
	require.NoError(t, listNamespaces(keyA.JWT), "tokens from a retired kid still work during grace")

	after := listSigningKeys(t, st.adminURL)
	require.Len(t, after, 2)
	require.NotNil(t, after[0].RetiredAt)
	require.False(t, after[0].Active)
	require.True(t, after[1].Active)

	status, body = retireSigningKey(t, st.adminURL, kidB[1])
	require.Equalf(t, http.StatusConflict, status, "the new key is now the only active one: %s", body)

	// --- after grace: the kid leaves JWKS, then Temporal rejects its tokens ---
	require.Eventually(t, func() bool {
		return !slices.Contains(jwksKids(t, st.publicURL), kidA)
	}, e2eRetirementGrace+15*time.Second, time.Second, "the retired kid must leave JWKS after grace")
	require.Equal(t, []string{kidB[1]}, jwksKids(t, st.publicURL))

	require.Eventually(t, func() bool { return listNamespaces(keyA.JWT) != nil },
		45*time.Second, time.Second,
		"once Temporal refreshes its JWKS, a token signed by the retired kid must be rejected even though it has not expired")
	require.NoError(t, listNamespaces(keyB.JWT), "tokens from the active key keep working")

	require.Equal(t, http.StatusUnauthorized, userinfoStatus(t, st.publicURL, keyA.JWT),
		"tempogate's own verifier must stop accepting a kid past grace")
	require.Equal(t, http.StatusOK, userinfoStatus(t, st.publicURL, keyB.JWT))

	require.Equal(t, startedAt, containerStartedAt(ctx, t, st.tempogate), "tempogate must not have restarted")
}

func tokenKid(t *testing.T, raw string) string {
	t.Helper()
	msg, err := jws.Parse([]byte(raw))
	require.NoError(t, err)
	kid, ok := msg.Signatures()[0].ProtectedHeaders().KeyID()
	require.True(t, ok, "tempogate tokens carry a kid header")
	return kid
}

// execTempogate runs a tempogate subcommand inside the serving container, so
// it shares the state volume and env exactly as an operator's `kubectl exec`
// would, and returns its combined output.
func execTempogate(ctx context.Context, t *testing.T, c testcontainers.Container, args ...string) string {
	t.Helper()
	code, r, err := c.Exec(ctx, append([]string{"/tempogate"}, args...), tcexec.Multiplexed())
	require.NoError(t, err)
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equalf(t, 0, code, "tempogate %s: %s", strings.Join(args, " "), out)
	return string(out)
}

func listSigningKeys(t *testing.T, adminURL string) []signingKeyView {
	t.Helper()
	status, b := adminRequest(t, http.MethodGet, adminURL+"/admin/signing-keys", "", e2eAdminToken, "")
	require.Equalf(t, http.StatusOK, status, "GET /admin/signing-keys: %s", b)
	var out struct {
		Items []signingKeyView `json:"items"`
	}
	require.NoError(t, json.Unmarshal(b, &out))
	return out.Items
}

func retireSigningKey(t *testing.T, adminURL, kid string) (int, []byte) {
	t.Helper()
	return adminRequest(t, http.MethodPost, adminURL+"/admin/signing-keys/"+kid+"/retire", "", e2eAdminToken, "")
}

func jwksKids(t *testing.T, publicURL string) []string {
	t.Helper()
	resp, err := http.Get(publicURL + "/.well-known/jwks.json")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var doc struct {
		Keys []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&doc))
	out := make([]string, 0, len(doc.Keys))
	for _, k := range doc.Keys {
		out = append(out, k.Kid)
	}
	return out
}

func containerStartedAt(ctx context.Context, t *testing.T, c testcontainers.Container) string {
	t.Helper()
	state, err := c.State(ctx)
	require.NoError(t, err)
	return state.StartedAt
}

// ---------- stack bring-up ----------

func setupIntegrationKeysStack(ctx context.Context, t *testing.T) *integrationKeysStack {
	t.Helper()

	net, err := tcnetwork.New(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = net.Remove(ctx) })
	netName := net.Name
	alias := func(name string) map[string][]string { return map[string][]string{netName: {name}} }

	// This stack mints a temporal-system:admin key, so it opts into system
	// grants; TestAdminRefusesSystemGrantByDefault covers the default.
	tempogate := startIntegrationKeysTempogate(ctx, t, netName, true)

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

// startIntegrationKeysTempogate migrates a fresh state volume and starts
// `tempogate serve` on netName with both listeners exposed.
func startIntegrationKeysTempogate(ctx context.Context, t *testing.T, netName string, allowSystemGrants bool) testcontainers.Container {
	t.Helper()
	root := repoRoot(t)

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
		// Short enough for TestSigningKeyRotationAndRetirement to watch a
		// retired kid leave JWKS, long enough to observe it during grace.
		"KEYS_RETIREMENT_GRACE": e2eRetirementGrace.String(),
		"KEYS_RELOAD_INTERVAL":  "1s",
		"KEYS_PUBLISH_DELAY":    e2ePublishDelay.String(),
	}
	addDeviceUIServerEnv(tgEnv, tempogateIssuer)
	addAdminAuthEnv(ctx, t, tgEnv, allowSystemGrants)
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
			NetworkAliases: map[string][]string{netName: {"tempogate"}},
			WaitingFor: wait.ForAll(
				wait.ForHTTP("/readyz").WithPort("8000/tcp"),
				wait.ForHTTP("/admin/healthz").WithPort("8081/tcp"),
			).WithStartupTimeoutDefault(2 * time.Minute),
		},
		Started: true,
	})
	require.NoError(t, err, "tempogate serve")
	track(ctx, t, "tempogate", tempogate)
	return tempogate
}
