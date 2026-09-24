//go:build e2e

// Package e2e is the acceptance proof for the Temporal Web UI SSO story: a
// real temporalio/ui container, configured only via TEMPORAL_AUTH_* env vars,
// federates an OIDC login through a tempogate container to a mock Google IdP,
// receives a tempogate-signed JWT, and that JWT authenticates a gRPC call to a
// real temporal-frontend whose default authorizer is JWKS-backed by tempogate.
//
// Everything runs as containers on one Docker network so service-to-service
// and browser-to-service traffic share the same hostnames; the test process
// drives a containerised headless Chrome over its mapped DevTools port and
// talks gRPC over the frontend's mapped port. Gated behind `//go:build e2e`
// (and a dedicated CI job) so the fast unit suite stays fast.
package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcnetwork "github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.temporal.io/api/workflowservice/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Pinned images keep CI deterministic; override via env to bump without a
// code change. The Temporal auth env-var templating these rely on has been in
// the auto-setup config_template.yaml for many releases.
var (
	postgresImage = imageOr("E2E_POSTGRES_IMAGE", "postgres:16-alpine")
	temporalImage = imageOr("E2E_TEMPORAL_IMAGE", "temporalio/auto-setup:1.25.2")
	uiImage       = imageOr("E2E_TEMPORAL_UI_IMAGE", "temporalio/ui:2.32.0")
	chromeImage   = imageOr("E2E_CHROME_IMAGE", "chromedp/headless-shell:131.0.6778.86")
)

const (
	clientID     = "temporal-ui"
	clientSecret = "e2e-temporal-ui-confidential-secret"
	allowedEmail = "alice@example.com"
	deniedEmail  = "intruder@evil.test"

	tempogateIssuer = "http://tempogate:8000"
	uiCallback      = "http://temporal-ui:8080/auth/sso/callback"
	mockIssuer      = "http://mockgoogle:8080"
)

func imageOr(env, def string) string {
	if v := os.Getenv(env); v != "" {
		return v
	}
	return def
}

// builtImageSource decides whether a container is run from a pre-built image
// or built in-test. Both Dockerfiles use BuildKit-only syntax (`# syntax=`,
// `RUN --mount`), but testcontainers builds via Docker's classic builder,
// which cannot parse those. So `make test-e2e` (and CI) pre-builds them with a
// BuildKit-capable `docker build` and passes the tag via env; the
// FromDockerfile path remains only as a fallback for environments whose
// builder can handle BuildKit syntax.
func builtImageSource(envVar, dockerfile, root string) (string, testcontainers.FromDockerfile) {
	if v := os.Getenv(envVar); v != "" {
		return v, testcontainers.FromDockerfile{}
	}
	return "", testcontainers.FromDockerfile{Context: root, Dockerfile: dockerfile, KeepImage: true}
}

// stack holds the host-reachable endpoints the test process needs; everything
// else addresses peers by Docker network alias.
type stack struct {
	mockBaseURL  string // http://host:port to set the mock identity
	uiInternal   string // http://temporal-ui:8080 (browser, on the network)
	frontendAddr string // host:port for the gRPC client
	chromeWS     string // DevTools websocket for chromedp
}

func TestWebUISSO(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e: skipped in -short")
	}
	ctx := context.Background()
	st := setupStack(ctx, t)

	t.Run("happy path: SSO mints an admin JWT ready on first load, and gRPC ListNamespaces succeeds", func(t *testing.T) {
		st.setIdentity(t, allowedEmail, true)
		jwtStr := st.driveLoginAndExtractJWT(ctx, t)

		// (3) The JWT is ready on the first authenticated load: it was in the
		// session cookie the moment the browser landed back, with full perms.
		tok, err := jwt.ParseInsecure([]byte(jwtStr))
		require.NoError(t, err, "session cookie must carry a parseable tempogate JWT")

		iss, _ := tok.Issuer()
		require.Equal(t, tempogateIssuer, iss)
		aud, _ := tok.Audience()
		require.Contains(t, aud, clientID, "OIDC aud must be the UI's client_id")
		require.True(t, tok.Has("nonce"), "nonce must round-trip so the UI accepts the token")
		perms, ok := tok.Field("permissions")
		require.True(t, ok)
		require.Equal(t, []any{"temporal-system:admin"}, perms, "flat Hour-0 authz: System Admin (Temporal's default ClaimMapper has no namespace wildcard)")
		sub, _ := tok.Subject()
		require.Equal(t, allowedEmail, sub)

		// (1) The same JWT authenticates a real gRPC call to temporal-frontend,
		// whose default authorizer is JWKS-backed by tempogate.
		client, conn := dialFrontend(t, st.frontendAddr)
		defer conn.Close()

		authed := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+jwtStr)
		resp, err := client.ListNamespaces(authed, &workflowservice.ListNamespacesRequest{PageSize: 10})
		require.NoError(t, err, "tempogate JWT must pass Temporal's default ClaimMapper")
		require.NotEmpty(t, resp.GetNamespaces(), "admin token should see namespaces")

		// Authorization is genuinely enforced: no token is rejected.
		_, err = client.ListNamespaces(ctx, &workflowservice.ListNamespacesRequest{PageSize: 10})
		require.Error(t, err, "frontend must reject an unauthenticated call")
		require.Contains(t,
			[]codes.Code{codes.Unauthenticated, codes.PermissionDenied},
			status.Code(err),
			"unexpected status: %v", err)
	})

	t.Run("disallowed domain bounces to 403", func(t *testing.T) {
		st.setIdentity(t, deniedEmail, true)
		body := st.driveLoginExpectingForbidden(ctx, t)
		require.Contains(t, body, "Access denied")
		require.Contains(t, body, "not in an allowed domain")
	})
}

// ---------- stack bring-up ----------

func setupStack(ctx context.Context, t *testing.T) *stack {
	t.Helper()
	root := repoRoot(t)

	net, err := tcnetwork.New(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = net.Remove(ctx) })
	netName := net.Name

	alias := func(name string) map[string][]string { return map[string][]string{netName: {name}} }

	// --- mock Google ---
	mockImg, mockFrom := builtImageSource("E2E_MOCKGOOGLE_IMAGE", "test/e2e/mockgoogle/Dockerfile", root)
	mock, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:          mockImg,
			FromDockerfile: mockFrom,
			Env:            map[string]string{"MOCK_ISSUER": mockIssuer},
			ExposedPorts:   []string{"8080/tcp"},
			Networks:       []string{netName},
			NetworkAliases: alias("mockgoogle"),
			WaitingFor:     wait.ForHTTP("/healthz").WithPort("8080/tcp").WithStartupTimeout(2 * time.Minute),
		},
		Started: true,
	})
	require.NoError(t, err, "mockgoogle")
	track(ctx, t, "mockgoogle", mock)
	mockBase := mappedHTTP(ctx, t, mock, "8080")

	// --- tempogate: migrate (one-shot) then serve, sharing a volume ---
	tgEnv := map[string]string{
		"HTTP_LISTENER":              "0.0.0.0:8000",
		"STATE_SQLITE_PATH":          "/state/state.db",
		"OIDC_ISSUER":                tempogateIssuer,
		"OIDC_CLIENTS":               clientID + ":" + uiCallback,
		"OIDC_CLIENT_SECRETS":        clientID + ":" + clientSecret,
		"OIDC_ALLOWED_DOMAINS":       "example.com",
		"OIDC_GOOGLE_CLIENT_ID":      "tempogate-upstream",
		"OIDC_GOOGLE_CLIENT_SECRET":  "tempogate-upstream-secret",
		"OIDC_GOOGLE_AUTH_ENDPOINT":  mockIssuer + "/auth",
		"OIDC_GOOGLE_TOKEN_ENDPOINT": mockIssuer + "/token",
		"OIDC_GOOGLE_ISSUER_URL":     mockIssuer,
	}
	// The temporal-UI SSO surface this test exercises doesn't touch the
	// device flow, but the server fx graph now requires the verification
	// UI's internal client + signing key regardless — addDeviceUIServerEnv
	// appends them.
	addDeviceUIServerEnv(tgEnv, tempogateIssuer)
	stateVol := fmt.Sprintf("tempogate-e2e-state-%d", time.Now().UnixNano())
	tgImg, tgFrom := builtImageSource("E2E_TEMPOGATE_IMAGE", "Dockerfile", root)

	migrate, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:          tgImg,
			FromDockerfile: tgFrom,
			Cmd:            []string{"migrate"},
			Env:            tgEnv,
			User:           "0:0", // shared named volume; run as root so serve can reopen the file
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
			ExposedPorts:   []string{"8000/tcp"},
			Networks:       []string{netName},
			NetworkAliases: alias("tempogate"),
			WaitingFor: wait.ForHTTP("/readyz").WithPort("8000/tcp").
				WithStartupTimeout(2 * time.Minute),
		},
		Started: true,
	})
	require.NoError(t, err, "tempogate serve")
	track(ctx, t, "tempogate", tempogate)

	// --- postgres for Temporal ---
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

	// --- temporal-frontend (auto-setup) with JWKS-backed default authorizer ---
	temporal, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image: temporalImage,
			Env: map[string]string{
				"DB": "postgres12", "DB_PORT": "5432",
				"POSTGRES_USER": "temporal", "POSTGRES_PWD": "temporal",
				"POSTGRES_SEEDS": "db", "DBNAME": "temporal",
				"BIND_ON_IP": "0.0.0.0", // frontend must be reachable off-loopback
				// With the JWT authorizer on, Temporal's own internal worker
				// would call the (authorizing) frontend with no token and
				// fatally fail its system scanners; the internal frontend
				// gives internal traffic an unauthorized bypass while the
				// external 7233 still enforces the JWT. And auto-setup's
				// default-namespace registration is itself an authorized call
				// that its `set -e` script cannot survive — skip it; the
				// schema-bootstrapped temporal-system namespace is enough for
				// ListNamespaces to be non-empty.
				"USE_INTERNAL_FRONTEND":           "true",
				"SKIP_DEFAULT_NAMESPACE_CREATION": "true",
				// USE_INTERNAL_FRONTEND only renders the config block and drops
				// publicClient; auto-setup still starts the *default* service
				// set (no internal-frontend), so the service must be requested
				// explicitly or the worker has nowhere to connect and the
				// container crashes after "Temporal server started".
				"SERVICES": "frontend:internal-frontend:history:matching:worker",
				// Stock config_template.yaml templates the authorization block
				// from exactly these env vars.
				"TEMPORAL_JWT_KEY_SOURCE1":   tempogateIssuer + "/.well-known/jwks.json",
				"TEMPORAL_JWT_KEY_REFRESH":   "10s",
				"TEMPORAL_AUTH_AUTHORIZER":   "default",
				"TEMPORAL_AUTH_CLAIM_MAPPER": "default",
			},
			ExposedPorts:   []string{"7233/tcp"},
			Networks:       []string{netName},
			NetworkAliases: alias("temporal"),
			WaitingFor: wait.ForLog("Temporal server started").
				WithStartupTimeout(4 * time.Minute),
		},
		Started: true,
	})
	require.NoError(t, err, "temporal")
	track(ctx, t, "temporal", temporal)

	// --- temporal-ui, configured only via TEMPORAL_AUTH_* ---
	ui, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image: uiImage,
			Env: map[string]string{
				"TEMPORAL_ADDRESS":            "temporal:7233",
				"TEMPORAL_UI_PORT":            "8080",
				"TEMPORAL_AUTH_ENABLED":       "true",
				"TEMPORAL_AUTH_TYPE":          "oidc",
				"TEMPORAL_AUTH_PROVIDER_URL":  tempogateIssuer,
				"TEMPORAL_AUTH_ISSUER_URL":    tempogateIssuer,
				"TEMPORAL_AUTH_CLIENT_ID":     clientID,
				"TEMPORAL_AUTH_CLIENT_SECRET": clientSecret,
				"TEMPORAL_AUTH_CALLBACK_URL":  uiCallback,
				"TEMPORAL_AUTH_SCOPES":        "openid email",
			},
			ExposedPorts:   []string{"8080/tcp"},
			Networks:       []string{netName},
			NetworkAliases: alias("temporal-ui"),
			WaitingFor: wait.ForHTTP("/").WithPort("8080/tcp").
				WithStartupTimeout(2 * time.Minute),
		},
		Started: true,
	})
	require.NoError(t, err, "temporal-ui")
	track(ctx, t, "temporal-ui", ui)

	// --- headless Chrome on the network so it resolves the aliases ---
	chrome, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image: chromeImage,
			Cmd: []string{
				"--remote-debugging-address=0.0.0.0", "--remote-debugging-port=9222",
				"--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage",
			},
			ExposedPorts:   []string{"9222/tcp"},
			Networks:       []string{netName},
			NetworkAliases: alias("chrome"),
			WaitingFor: wait.ForHTTP("/json/version").WithPort("9222/tcp").
				WithStartupTimeout(2 * time.Minute),
		},
		Started: true,
	})
	require.NoError(t, err, "chrome")
	track(ctx, t, "chrome", chrome)

	return &stack{
		mockBaseURL:  mockBase,
		uiInternal:   "http://temporal-ui:8080",
		frontendAddr: mappedAddr(ctx, t, temporal, "7233"),
		chromeWS:     devtoolsWS(ctx, t, chrome),
	}
}

// ---------- browser flow ----------

// driveLoginAndExtractJWT runs the full SSO chain in headless Chrome and
// returns the tempogate JWT the Temporal UI's SPA carries on its
// authenticated API calls — the same token the session was minted from.
func (s *stack) driveLoginAndExtractJWT(ctx context.Context, t *testing.T) string {
	t.Helper()
	browserCtx, cancel := s.browser(ctx, t)
	defer cancel()

	// The UI hands the token to its SPA via a short-lived (60s), SPA-consumed
	// user* cookie — racy to read, and cross-origin target swaps make a
	// Set-Cookie capture flaky. After login the SPA instead attaches the
	// token as `Authorization: Bearer <jwt>` to every /api/v1 call (ui-server
	// requires that header), all same-origin on the settled page. Capturing
	// that outgoing request header is deterministic and lifetime-independent.
	bc := &bearerCatcher{done: make(chan string, 1)}
	chromedp.ListenTarget(browserCtx, bc.onEvent)

	err := chromedp.Run(browserCtx,
		network.Enable(),
		network.ClearBrowserCookies(),
		chromedp.Navigate(s.uiInternal+"/auth/sso?returnUrl=/namespaces"),
		chromedp.WaitVisible(`#approve`, chromedp.ByID), // mock Google consent screen
		chromedp.Click(`#approve`, chromedp.ByID),
	)
	require.NoError(t, err, "SSO browser flow (consent)")

	select {
	case jwtStr := <-bc.done:
		return jwtStr
	case <-time.After(90 * time.Second):
		t.Fatal("e2e: SPA never sent an authenticated /api/v1 request after SSO")
		return ""
	}
}

// driveLoginExpectingForbidden runs the chain for a disallowed identity and
// returns the body text the browser ends on (tempogate's 403 page).
func (s *stack) driveLoginExpectingForbidden(ctx context.Context, t *testing.T) string {
	t.Helper()
	browserCtx, cancel := s.browser(ctx, t)
	defer cancel()

	var body string
	err := chromedp.Run(browserCtx,
		network.Enable(),
		network.ClearBrowserCookies(),
		chromedp.Navigate(s.uiInternal+"/auth/sso"),
		chromedp.WaitVisible(`#approve`, chromedp.ByID),
		chromedp.Click(`#approve`, chromedp.ByID),
		chromedp.Sleep(3*time.Second), // let the redirect chain settle on tempogate's 403
		chromedp.Text(`body`, &body, chromedp.ByQuery),
	)
	require.NoError(t, err, "forbidden browser flow")
	return body
}

func (s *stack) browser(ctx context.Context, t *testing.T) (context.Context, context.CancelFunc) {
	allocCtx, cancelAlloc := chromedp.NewRemoteAllocator(ctx, s.chromeWS)
	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx)
	t.Cleanup(cancelBrowser)
	t.Cleanup(cancelAlloc)
	return browserCtx, func() { cancelBrowser(); cancelAlloc() }
}

// bearerCatcher captures the tempogate JWT the Temporal UI's SPA attaches as
// `Authorization: Bearer <jwt>` to its /api/v1 calls after login. ui-server's
// ValidateAuthHeaderExists mandates that header, so a 200 from /api/v1 means
// the SPA holds the token; intercepting the outgoing request header is
// deterministic and immune to the handoff cookie's 60s lifetime / SPA
// consumption. These XHRs are same-origin on the settled post-login page, so
// the listener is not affected by the earlier cross-origin target swaps.
type bearerCatcher struct {
	done chan string
	once sync.Once
}

func (bc *bearerCatcher) onEvent(ev interface{}) {
	e, ok := ev.(*network.EventRequestWillBeSent)
	if !ok || e.Request == nil || !strings.Contains(e.Request.URL, "/api/v1/") {
		return
	}
	const prefix = "Bearer "
	for k, v := range e.Request.Headers {
		if !strings.EqualFold(k, "authorization") {
			continue
		}
		s, _ := v.(string)
		if len(s) > len(prefix) && strings.EqualFold(s[:len(prefix)], prefix) {
			tok := strings.TrimSpace(s[len(prefix):])
			bc.once.Do(func() { bc.done <- tok })
		}
	}
}

// ---------- helpers ----------

func (s *stack) setIdentity(t *testing.T, email string, verified bool) {
	t.Helper()
	form := url.Values{"email": {email}, "verified": {fmt.Sprintf("%t", verified)}}
	req, err := http.NewRequest(http.MethodPut, s.mockBaseURL+"/_control/identity",
		strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
}

func dialFrontend(t *testing.T, addr string) (workflowservice.WorkflowServiceClient, *grpc.ClientConn) {
	t.Helper()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	return workflowservice.NewWorkflowServiceClient(conn), conn
}

func mappedAddr(ctx context.Context, t *testing.T, c testcontainers.Container, port string) string {
	t.Helper()
	host, err := c.Host(ctx)
	require.NoError(t, err)
	p, err := c.MappedPort(ctx, port+"/tcp")
	require.NoError(t, err)
	return fmt.Sprintf("%s:%s", host, p.Port())
}

func mappedHTTP(ctx context.Context, t *testing.T, c testcontainers.Container, port string) string {
	return "http://" + mappedAddr(ctx, t, c, port)
}

// devtoolsWS resolves the headless-shell DevTools websocket and rewrites its
// host to the mapped host:port the test process can reach.
func devtoolsWS(ctx context.Context, t *testing.T, c testcontainers.Container) string {
	t.Helper()
	base := mappedHTTP(ctx, t, c, "9222")
	var info struct {
		WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
	}
	require.Eventually(t, func() bool {
		resp, err := http.Get(base + "/json/version")
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		return json.NewDecoder(resp.Body).Decode(&info) == nil && info.WebSocketDebuggerURL != ""
	}, 60*time.Second, time.Second, "DevTools endpoint never came up")

	u, err := url.Parse(info.WebSocketDebuggerURL)
	require.NoError(t, err)
	mapped, err := url.Parse(base)
	require.NoError(t, err)
	u.Host = mapped.Host
	return u.String()
}

// track registers cleanups so that, when the test fails, every container's
// logs are dumped before it is torn down. t.Cleanup is LIFO, so the
// log-dump (registered last) runs before Terminate (registered first) and
// the logs are still available. This is what makes a CI failure
// self-diagnosing instead of an opaque "container exited with code 1".
func track(ctx context.Context, t *testing.T, name string, c testcontainers.Container) {
	t.Helper()
	t.Cleanup(func() { _ = c.Terminate(ctx) })
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		rc, err := c.Logs(ctx)
		if err != nil {
			t.Logf("e2e: %s: logs unavailable: %v", name, err)
			return
		}
		defer func() { _ = rc.Close() }()
		b, _ := io.ReadAll(rc)
		t.Logf("=== %s container logs ===\n%s\n=== end %s logs ===", name, b, name)
	})
}

func repoRoot(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("..", ".."))
	require.NoError(t, err)
	return abs
}
