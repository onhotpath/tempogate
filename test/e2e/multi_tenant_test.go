//go:build e2e

// Acceptance proof for namespace-scoped multi-tenancy: a tempogate-minted JWT
// authorizes only on the namespaces named in its `permissions` claim, and
// every other namespace returns gRPC PermissionDenied at the temporal-frontend
// boundary. The same harness as the integration-keys test (one tempogate, one
// temporal-frontend with the JWKS-backed default authorizer + default
// ClaimMapper, postgres for Temporal) is reused so the only new variable is
// the permissions-claim shape under test.
//
// The test covers two distinct scopes:
//
//  1. Single-namespace integration key — minted via the admin API. Proves the
//     production-surface key shape (one namespace + one role per key) really
//     does scope the token: ops on the granted namespace succeed, ops on a
//     sibling namespace are denied at the frontend with code PermissionDenied.
//
//  2. Multi-namespace token — minted in-process by signing with the same
//     keypair the running tempogate published in its JWKS. Proves that
//     Temporal's default ClaimMapper accumulates DIFFERENT-namespace entries
//     from a single `permissions` array into independent (ns, role) decisions:
//     a token with `tenant-a:admin` and `tenant-b:read` authorizes admin ops
//     on tenant-a, read ops on tenant-b, and is denied on writes to tenant-b.
//
// On the S1 spike: the default ClaimMapper's last-write-wins behaviour is
// scoped to duplicate entries for the SAME namespace; different namespaces
// accumulate independently because they index into different keys of
// claims.Namespaces. The multi-ns assertions below codify that — if a future
// Temporal change collapsed the array across namespaces (the hypothetical
// "last-write-wins across the whole array" failure mode) the tenant-a admin
// op would be denied because tenant-a's grant would be overwritten by
// tenant-b:read. That counterfactual is what makes the test meaningful.
//
// The in-process minting helper (mintInProcess) sidesteps extending the
// admin API into a multi-permission surface: the production API stays
// deliberately single-namespace per key (one (ns, role) per row, the simplest
// scope that audit and rotation can reason about), and the test borrows the
// signer/keypair the container itself uses so the resulting JWT verifies
// under the exact JWKS Temporal is polling.
package e2e

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcnetwork "github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
	commonpb "go.temporal.io/api/common/v1"
	"go.temporal.io/api/serviceerror"
	taskqueuepb "go.temporal.io/api/taskqueue/v1"
	"go.temporal.io/api/workflowservice/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/onhotpath/tempogate/keys"
	"github.com/onhotpath/tempogate/perms"
	"github.com/onhotpath/tempogate/state/sqlite"
)

const (
	tenantA = "tenant-a"
	tenantB = "tenant-b"
)

type multiTenantStack struct {
	tempogate    testcontainers.Container
	publicURL    string
	adminURL     string
	frontendAddr string
}

func TestMultiTenantNamespaceScoping(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e: skipped in -short")
	}
	ctx := context.Background()
	st := setupMultiTenantStack(ctx, t)

	// Bootstrap: mint a system-admin key and use it to register the two
	// tenant namespaces on temporal-frontend. RegisterNamespace is a
	// cluster-level admin op (Temporal's default authorizer only honours it
	// for claims.System >= admin), so a temporal-system:admin token is
	// required regardless of the per-tenant tokens this test then mints.
	bootstrap := mintIntegrationKey(t, st.adminURL, adminCreateBody{
		Namespace: "temporal-system",
		Role:      "admin",
		Owner:     "e2e-multitenant-bootstrap",
	})
	client, conn := dialFrontend(t, st.frontendAddr)
	defer func() { _ = conn.Close() }()
	bootstrapCtx := withBearer(ctx, bootstrap.JWT)
	registerNamespace(t, bootstrapCtx, client, tenantA)
	registerNamespace(t, bootstrapCtx, client, tenantB)
	waitForNamespace(t, bootstrapCtx, client, tenantA)
	waitForNamespace(t, bootstrapCtx, client, tenantB)

	t.Run("single-namespace integration key denies cross-namespace ops", func(t *testing.T) {
		key := mintIntegrationKey(t, st.adminURL, adminCreateBody{
			Namespace: tenantA,
			Role:      "admin",
			Owner:     "e2e-multitenant-single-ns",
		})
		authed := withBearer(ctx, key.JWT)

		// Sanity: the token authorizes ops on the namespace it was granted.
		// DescribeNamespace exercises the read path; UpdateNamespace
		// exercises the admin path. Both are namespace-scoped so a missing
		// grant on this namespace would surface as PermissionDenied, not as
		// a not-found.
		_, err := client.DescribeNamespace(authed, &workflowservice.DescribeNamespaceRequest{Namespace: tenantA})
		require.NoError(t, err, "tenant-a:admin token must read its own namespace")

		_, err = client.UpdateNamespace(authed, &workflowservice.UpdateNamespaceRequest{Namespace: tenantA})
		require.NoError(t, err, "tenant-a:admin token must perform admin ops on its own namespace")

		// Cross-namespace denial — the central assertion of this test. A
		// PermissionDenied here proves the default authorizer is keying on
		// the request's namespace, not on the token's signature alone.
		_, err = client.DescribeNamespace(authed, &workflowservice.DescribeNamespaceRequest{Namespace: tenantB})
		requirePermissionDenied(t, err, "tenant-a:admin token must NOT read tenant-b")

		_, err = client.StartWorkflowExecution(authed, startWorkflowReq(tenantB))
		requirePermissionDenied(t, err, "tenant-a:admin token must NOT write to tenant-b")
	})

	t.Run("multi-namespace token honours per-namespace roles independently", func(t *testing.T) {
		// `tenant-a:admin` + `tenant-b:read`. The grant is serialized as a
		// two-entry permissions claim; Temporal's default ClaimMapper
		// accumulates the entries into claims.Namespaces independently
		// because the keys differ. Were the array collapsed across
		// namespaces (the S1 last-write-wins counterfactual) the
		// tenant-a admin assertion below would fail because tenant-a's
		// grant would be lost when tenant-b's was applied.
		jwtStr := mintInProcess(ctx, t, st.tempogate,
			"e2e-multitenant-multi-ns",
			perms.New(
				perms.AddNamespace(tenantA, perms.RoleAdmin),
				perms.AddNamespace(tenantB, perms.RoleRead),
			),
		)
		authed := withBearer(ctx, jwtStr)

		_, err := client.UpdateNamespace(authed, &workflowservice.UpdateNamespaceRequest{Namespace: tenantA})
		require.NoError(t, err, "tenant-a:admin entry must authorize admin ops on tenant-a")

		_, err = client.DescribeNamespace(authed, &workflowservice.DescribeNamespaceRequest{Namespace: tenantB})
		require.NoError(t, err, "tenant-b:read entry must authorize read ops on tenant-b")

		_, err = client.StartWorkflowExecution(authed, startWorkflowReq(tenantB))
		requirePermissionDenied(t, err, "tenant-b:read entry must NOT authorize writes to tenant-b")
	})
}

// withBearer is the one-liner that puts a Bearer header on an outbound gRPC
// call. Inlined elsewhere in the e2e suite; pulled out here because every
// assertion below threads a different token through the same client.
func withBearer(ctx context.Context, jwtStr string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+jwtStr)
}

// requirePermissionDenied is the assertion the cross-namespace deny path
// pivots on. The Temporal default authorizer maps an unauthorized op to gRPC
// PermissionDenied (NOT Unauthenticated — the token is signature-valid; what
// fails is the namespace-scoped role check). Using status.Code keeps the
// assertion robust to wrapper changes in go.temporal.io/api/serviceerror.
func requirePermissionDenied(t *testing.T, err error, msg string) {
	t.Helper()
	require.Error(t, err, msg)
	require.Equalf(t, codes.PermissionDenied, status.Code(err),
		"%s — got %v", msg, err)
}

func registerNamespace(t *testing.T, ctx context.Context, c workflowservice.WorkflowServiceClient, ns string) {
	t.Helper()
	_, err := c.RegisterNamespace(ctx, &workflowservice.RegisterNamespaceRequest{
		Namespace: ns,
		// Retention has to be >= 1 day per Temporal validation; the workflows
		// this test starts never run (no worker), so the value is functional
		// only as a "valid register" placeholder.
		WorkflowExecutionRetentionPeriod: durationpb.New(24 * time.Hour),
		OwnerEmail:                       "e2e@tempogate.invalid",
	})
	// Re-runs of the suite against a sticky environment land here as
	// NamespaceAlreadyExists; idempotency keeps the bootstrap path
	// re-entrant without forcing the harness to track namespace lifetime.
	var alreadyExists *serviceerror.NamespaceAlreadyExists
	if err != nil && !errors.As(err, &alreadyExists) {
		require.NoErrorf(t, err, "RegisterNamespace(%s)", ns)
	}
}

// waitForNamespace blocks until DescribeNamespace stops returning NotFound.
// Temporal's namespace registration writes to persistence synchronously but
// the matching/history caches are repopulated lazily, so the immediate next
// authorized call on a freshly-registered namespace can race a NotFound;
// polling DescribeNamespace until it succeeds is the cheapest way to wait
// for the namespace to be observable on the read paths the test will hit.
func waitForNamespace(t *testing.T, ctx context.Context, c workflowservice.WorkflowServiceClient, ns string) {
	t.Helper()
	require.Eventuallyf(t, func() bool {
		_, err := c.DescribeNamespace(ctx, &workflowservice.DescribeNamespaceRequest{Namespace: ns})
		return err == nil
	}, 30*time.Second, 250*time.Millisecond, "namespace %s never became describable", ns)
}

// startWorkflowReq is a minimally-valid StartWorkflowExecution payload — just
// enough fields for the authorizer to reach a verdict (it only inspects
// Namespace) and for the frontend to not reject on shape. The workflow never
// runs because no worker is registered, but that does not matter: the call
// completes (returning a runID) when the namespace permits writes, and
// returns PermissionDenied before any of the fields below are validated when
// it does not.
func startWorkflowReq(ns string) *workflowservice.StartWorkflowExecutionRequest {
	return &workflowservice.StartWorkflowExecutionRequest{
		Namespace:    ns,
		WorkflowId:   "e2e-multitenant-" + uuid.NewString(),
		WorkflowType: &commonpb.WorkflowType{Name: "noop"},
		TaskQueue:    &taskqueuepb.TaskQueue{Name: "e2e-multitenant"},
		RequestId:    uuid.NewString(),
	}
}

// mintInProcess borrows the tempogate container's own signing keypair to
// produce a JWT with an arbitrary perms.Grant. The state file is copied off
// the container (including -wal and -shm so committed-but-not-checkpointed
// keypair rows are visible) and opened with the same pure-Go SQLite driver
// tempogate uses; the resulting Signer mints under the same kid the running
// tempogate published in its JWKS, so the temporal-frontend's JWKS-backed
// default authorizer accepts the token without any tempogate-side change.
//
// Why this lives in the e2e package instead of on the admin API: the
// production /admin/keys surface is deliberately single-namespace per key —
// one row per (ns, role) is the smallest scope audit and rotation can
// reason about. Multi-namespace tokens come out of the OIDC /token path for
// humans; for tests we want the same wire shape without taking on the
// product decision of exposing a multi-permission admin endpoint.
func mintInProcess(ctx context.Context, t *testing.T, c testcontainers.Container, subject string, grant *perms.Grant) string {
	t.Helper()
	dir := t.TempDir()
	local := filepath.Join(dir, "state.db")
	for _, suffix := range []string{"", "-wal", "-shm"} {
		err := copyFromContainerTo(ctx, c, "/state/state.db"+suffix, local+suffix)
		// Only state.db itself is mandatory; -wal/-shm are present only
		// when the writer holds the file open, which is the case here but
		// the assertion stays tolerant so a SQLite checkpoint-on-shutdown
		// would not silently brittle this helper.
		if suffix == "" {
			require.NoErrorf(t, err, "copy /state/state.db off container")
		}
	}

	store, err := sqlite.New(sqlite.WithPath(local), sqlite.WithBusyTimeout(2*time.Second))
	require.NoError(t, err, "open copied state.db with tempogate's sqlite driver")
	t.Cleanup(func() { _ = store.Close() })

	// Init loads the existing keypairs the running tempogate already
	// generated at first boot and populates the in-memory cache Signer
	// reads via Keys.Latest. It does NOT generate a new keypair when the
	// store is non-empty, so the Signer ends up using the same kid the
	// container's JWKS publishes.
	k := keys.New(keys.WithStore(store))
	require.NoError(t, k.Init(ctx))

	signer := keys.NewSigner(
		keys.WithKeys(k),
		keys.WithIssuer(tempogateIssuer),
	)
	signed, _, err := signer.Mint(ctx, keys.MintRequest{
		Subject:     subject,
		Permissions: grant.ToClaim(),
		// Five minutes is generous enough for a single test run and tight
		// enough that a leaked test token cannot be replayed against a
		// real-cluster JWKS for any meaningful window.
		TTL: 5 * time.Minute,
	})
	require.NoError(t, err, "in-process Mint")
	return signed
}

// ---------- stack bring-up ----------

func setupMultiTenantStack(ctx context.Context, t *testing.T) *multiTenantStack {
	t.Helper()
	root := repoRoot(t)

	net, err := tcnetwork.New(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = net.Remove(ctx) })
	netName := net.Name
	alias := func(name string) map[string][]string { return map[string][]string{netName: {name}} }

	// OIDC env vars point at non-routable upstreams: the OIDC surface is
	// always wired (the fx graph builds it unconditionally) but this test
	// never drives a /callback/google flow, so requiring a live mock Google
	// here would be wasted infra.
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
	stateVol := fmt.Sprintf("tempogate-multitenant-e2e-state-%d", time.Now().UnixNano())
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

	return &multiTenantStack{
		tempogate:    tempogate,
		publicURL:    mappedHTTP(ctx, t, tempogate, "8000"),
		adminURL:     mappedHTTP(ctx, t, tempogate, "8081"),
		frontendAddr: mappedAddr(ctx, t, temporal, "7233"),
	}
}
