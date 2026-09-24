//go:build e2e

// This file is the acceptance proof for the engineer-laptop story: a real
// `tempogate login` binary runs the loopback authorization-code flow against a
// tempogate container that federates to a mock Google, persists the token to
// ~/.tempogate/token.json, and that token authenticates a real gRPC call to a
// temporal-frontend whose default authorizer is JWKS-backed by tempogate.
// `tempogate token` is then exercised on both its fast path and its
// refresh-near-expiry path.
//
// Google loopback redirect strategy — resolved as **ephemeral
// port** (the recommended default; `tempogate login` is run here with no
// --port). This works with zero per-user identity-provider registration
// because the CLI never talks to Google directly: the only redirect Google
// (here, mockgoogle) ever sees is tempogate's own fixed /callback/google. The
// http://127.0.0.1:<ephemeral>/callback loopback URI is validated solely
// against tempogate's client-registry prefix (OIDC_CLIENTS contains
// `tempogate-cli:http://127.0.0.1:`), so a fresh ephemeral port each run needs
// no registration anywhere. See docs/cli-loopback-login.md.
//
// Topology note: `tempogate login` and the browser that drives the consent
// redirect run in ONE container (cliclient) on the shared Docker network. The
// loopback server binds 127.0.0.1 inside that container; the headless Chrome
// in the same container is the only browser that can reach it — exactly the
// network-namespace property a real laptop has, and one a separate browser
// container could not satisfy.
package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
	tcnetwork "github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.temporal.io/api/workflowservice/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/onhotpath/tempogate/cli"
)

const (
	cliClientID    = "tempogate-cli"
	cliTokenFile   = "/tmp/tg-token.json"
	cliAuthURLFile = "/tmp/tempogate-authurl"

	// e2eSessionSigningKeyB64 is "0123456789abcdef0123456789abcdef" — 32 ASCII
	// bytes, base64url-encoded without padding — the length the oidc fx graph
	// requires for OIDC_SESSION_SIGNING_KEY. Stable across runs so the
	// deployment is reproducible; the key is shared by every e2e setupCLIStack
	// caller (loopback + device-flow). It only protects the intra-cluster
	// verification-UI bounce, so a public test literal is fine.
	e2eSessionSigningKeyB64 = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY"
)

// addDeviceUIServerEnv layers onto an existing tempogate e2e env map the
// OIDC_* keys the server's fx graph has required since the device-flow
// verification UI's signed-cookie session work landed: the signing key,
// the internal `tempogate-device-ui` client (registered with a confidential
// secret), and its callback under callbackIssuer. Existing OIDC_CLIENTS /
// OIDC_CLIENT_SECRETS entries are preserved — the device-ui registration
// is appended — so harnesses that already register their own clients
// (loopback CLI, temporal-ui SSO, noop admin tests) keep working unchanged.
// callbackIssuer is the issuer URL the device-ui callback hangs off of
// (typically `tempogateIssuer`; for the path-prefixed test, the prefixed
// form so the registered redirect matches what the handler builds).
func addDeviceUIServerEnv(env map[string]string, callbackIssuer string) {
	deviceUIRegistration := deviceUIClientID + ":" + callbackIssuer + "/device/sso-callback"
	if existing := env["OIDC_CLIENTS"]; existing != "" {
		env["OIDC_CLIENTS"] = existing + "," + deviceUIRegistration
	} else {
		env["OIDC_CLIENTS"] = deviceUIRegistration
	}
	deviceUISecretEntry := deviceUIClientID + ":" + deviceUIClientSecret
	if existing := env["OIDC_CLIENT_SECRETS"]; existing != "" {
		env["OIDC_CLIENT_SECRETS"] = existing + "," + deviceUISecretEntry
	} else {
		env["OIDC_CLIENT_SECRETS"] = deviceUISecretEntry
	}
	env["OIDC_SESSION_SIGNING_KEY"] = e2eSessionSigningKeyB64
	env["OIDC_SESSION_TTL"] = "5m"
}

// jwtPattern matches a compact JWS (three base64url segments) so the token a
// subcommand prints can be lifted out of multiplexed exec output regardless of
// any incidental stderr.
var jwtPattern = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)

type cliStack struct {
	mockBaseURL      string // mapped http://host:port for mockgoogle
	tempogateBaseURL string // mapped http://host:port for tempogate
	frontendAddr     string
	client           testcontainers.Container
	chromeWS         string
}

func TestCLILogin(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e: skipped in -short")
	}
	ctx := context.Background()
	st := setupCLIStack(ctx, t)

	// Identity the mock asserts; example.com is tempogate's allowed domain.
	(&stack{mockBaseURL: st.mockBaseURL}).setIdentity(t, allowedEmail, true)

	// --- tempogate login: real binary, real loopback, browser-driven consent.
	loginDone := make(chan loginResult, 1)
	go func() {
		code, _, err := st.client.Exec(ctx,
			[]string{
				"tempogate", "login",
				"--issuer", tempogateIssuer,
				"--client-id", cliClientID,
				"--token-file", cliTokenFile,
			},
			tcexec.Multiplexed(),
		)
		loginDone <- loginResult{code: code, err: err}
	}()

	authURL := st.waitAuthURL(ctx, t)
	require.True(t,
		strings.HasPrefix(authURL, tempogateIssuer+"/authorize?"),
		"login must open tempogate's /authorize, got %q", authURL)
	require.Contains(t, authURL, "redirect_uri=http%3A%2F%2F127.0.0.1%3A",
		"the loopback redirect must be an ephemeral 127.0.0.1 port")
	require.Contains(t, authURL, "code_challenge_method=S256", "PKCE S256 is mandatory for the public CLI client")

	st.driveConsent(ctx, t, authURL)

	select {
	case r := <-loginDone:
		require.NoError(t, r.err, "tempogate login exec")
		require.Equal(t, 0, r.code, "tempogate login must exit 0")
	case <-time.After(2 * time.Minute):
		t.Fatal("e2e: tempogate login did not complete after consent")
	}

	// --- the persisted token file: 0600, and a usable tempogate JWT.
	require.Equal(t, "600", st.statMode(ctx, t, cliTokenFile),
		"~/.tempogate/token.json must be -rw------- (acceptance criterion)")
	tok := st.readToken(ctx, t)
	require.NotEmpty(t, tok.AccessToken)
	require.NotEmpty(t, tok.RefreshToken, "login must persist the refresh token for `tempogate token`")
	require.True(t, tok.ExpiresAt.After(time.Now().Add(3*time.Hour)),
		"a freshly minted access token should be ~4h out")

	assertTempogateJWT(t, tok.AccessToken)

	// --- the JWT authenticates a real gRPC call; an unauthenticated one is
	// genuinely rejected (authorization is enforced, not merely accepted).
	client, conn := dialFrontend(t, st.frontendAddr)
	defer func() { _ = conn.Close() }()

	authed := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+tok.AccessToken)
	resp, err := client.ListNamespaces(authed, &workflowservice.ListNamespacesRequest{PageSize: 10})
	require.NoError(t, err, "tempogate CLI JWT must pass Temporal's default ClaimMapper")
	require.NotEmpty(t, resp.GetNamespaces(), "admin token should see namespaces")

	_, err = client.ListNamespaces(ctx, &workflowservice.ListNamespacesRequest{PageSize: 10})
	require.Error(t, err, "frontend must reject an unauthenticated call")
	require.Contains(t,
		[]codes.Code{codes.Unauthenticated, codes.PermissionDenied},
		status.Code(err), "unexpected status: %v", err)

	// --- tempogate token, fast path: not near expiry ⇒ prints the stored
	// access token verbatim, no refresh.
	fast := st.runToken(ctx, t)
	require.Equal(t, tok.AccessToken, fast, "fast path must print the persisted access token unchanged")

	// --- tempogate token, refresh path: rewrite the file with a past expiry
	// (keeping the as-yet-unused refresh token) and prove the next invocation
	// transparently exchanges it, rewrites the file, and prints a new JWT.
	st.writeToken(ctx, t, cli.Token{
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		ExpiresAt:    time.Now().Add(-time.Minute),
	})
	refreshed := st.runToken(ctx, t)
	require.NotEqual(t, tok.AccessToken, refreshed, "an expiring token must be refreshed to a new JWT")
	assertTempogateJWT(t, refreshed)

	after := st.readToken(ctx, t)
	require.Equal(t, refreshed, after.AccessToken, "the refreshed token must be written back")
	require.NotEqual(t, tok.RefreshToken, after.RefreshToken, "the refresh token must rotate on use")
	require.True(t, after.ExpiresAt.After(time.Now().Add(3*time.Hour)), "the renewed token gets a fresh ~4h life")
}

type loginResult struct {
	code int
	err  error
}

func assertTempogateJWT(t *testing.T, raw string) {
	t.Helper()
	parsed, err := jwt.ParseInsecure([]byte(raw))
	require.NoError(t, err, "token must be a parseable tempogate JWT")
	iss, _ := parsed.Issuer()
	require.Equal(t, tempogateIssuer, iss)
	sub, _ := parsed.Subject()
	require.Equal(t, allowedEmail, sub)
	perms, ok := parsed.Field("permissions")
	require.True(t, ok)
	require.Equal(t, []any{"temporal-system:admin"}, perms,
		"flat Hour-0 authz: System Admin (Temporal's default ClaimMapper has no namespace wildcard)")
}

// ---------- cli-side helpers ----------

func (s *cliStack) waitAuthURL(ctx context.Context, t *testing.T) string {
	t.Helper()
	var url string
	require.Eventually(t, func() bool {
		code, r, err := s.client.Exec(ctx, []string{"cat", cliAuthURLFile}, tcexec.Multiplexed())
		if err != nil || code != 0 {
			return false
		}
		b, _ := io.ReadAll(r)
		url = strings.TrimSpace(string(b))
		return strings.HasPrefix(url, "http")
	}, 90*time.Second, 500*time.Millisecond, "tempogate login never published an authorize URL")
	return url
}

// driveConsent points the cliclient's headless Chrome at the authorize URL and
// clicks the mock consent's Approve link; the loopback callback (same
// container) then completes the flow.
func (s *cliStack) driveConsent(ctx context.Context, t *testing.T, authURL string) {
	t.Helper()
	allocCtx, cancelAlloc := chromedp.NewRemoteAllocator(ctx, s.chromeWS)
	t.Cleanup(cancelAlloc)
	bctx, cancelBrowser := chromedp.NewContext(allocCtx)
	t.Cleanup(cancelBrowser)

	err := chromedp.Run(bctx,
		chromedp.Navigate(authURL),
		chromedp.WaitVisible(`#approve`, chromedp.ByID), // mock Google consent
		chromedp.Click(`#approve`, chromedp.ByID),
	)
	require.NoError(t, err, "browser consent flow")
}

func (s *cliStack) statMode(ctx context.Context, t *testing.T, path string) string {
	t.Helper()
	code, r, err := s.client.Exec(ctx, []string{"stat", "-c", "%a", path}, tcexec.Multiplexed())
	require.NoError(t, err)
	require.Equal(t, 0, code, "stat %s", path)
	b, _ := io.ReadAll(r)
	return strings.TrimSpace(string(b))
}

func (s *cliStack) readToken(ctx context.Context, t *testing.T) cli.Token {
	t.Helper()
	rc, err := s.client.CopyFileFromContainer(ctx, cliTokenFile)
	require.NoError(t, err)
	defer func() { _ = rc.Close() }()
	var tok cli.Token
	require.NoError(t, json.NewDecoder(rc).Decode(&tok))
	return tok
}

func (s *cliStack) writeToken(ctx context.Context, t *testing.T, tok cli.Token) {
	t.Helper()
	b, err := json.Marshal(tok)
	require.NoError(t, err)
	require.NoError(t, s.client.CopyToContainer(ctx, b, cliTokenFile, 0o600))
}

// runToken runs `tempogate token` and returns the JWT it printed to stdout.
func (s *cliStack) runToken(ctx context.Context, t *testing.T) string {
	t.Helper()
	code, r, err := s.client.Exec(ctx,
		[]string{"tempogate", "token", "--issuer", tempogateIssuer, "--token-file", cliTokenFile},
		tcexec.Multiplexed(),
	)
	require.NoError(t, err)
	b, _ := io.ReadAll(r)
	require.Equalf(t, 0, code, "tempogate token failed: %s", b)
	m := jwtPattern.FindString(string(b))
	require.NotEmptyf(t, m, "tempogate token printed no JWT: %q", string(b))
	return m
}

// ---------- stack bring-up ----------

// setupCLIStack brings up tempogate + mockgoogle + temporal + cliclient (the
// shared headless-Chrome + tempogate-binary container). extraTempogateEnv is
// merged onto the base OIDC_* config so the device-flow acceptance proof can
// register its extra client_ids + signing key without forcing the loopback
// proof to carry inert config.
func setupCLIStack(ctx context.Context, t *testing.T, extraTempogateEnv ...map[string]string) *cliStack {
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

	// --- tempogate: migrate then serve. The CLI is registered as a *public*
	// client (no secret ⇒ PKCE mandatory) with a 127.0.0.1: redirect prefix,
	// so any ephemeral loopback port is accepted. The device-flow CLI
	// (tempogate-device) goes in too so TestCLIDeviceLogin can reuse this
	// stack; addDeviceUIServerEnv adds the verification-UI's internal
	// client + session signing key the server fx graph requires.
	tgEnv := map[string]string{
		"HTTP_LISTENER":              "0.0.0.0:8000",
		"STATE_SQLITE_PATH":          "/state/state.db",
		"OIDC_ISSUER":                tempogateIssuer,
		"OIDC_CLIENTS":               cliClientID + ":http://127.0.0.1:," + deviceClientID + ":cli",
		"OIDC_ALLOWED_DOMAINS":       "example.com",
		"OIDC_GOOGLE_CLIENT_ID":      "tempogate-upstream",
		"OIDC_GOOGLE_CLIENT_SECRET":  "tempogate-upstream-secret",
		"OIDC_GOOGLE_AUTH_ENDPOINT":  mockIssuer + "/auth",
		"OIDC_GOOGLE_TOKEN_ENDPOINT": mockIssuer + "/token",
		"OIDC_GOOGLE_ISSUER_URL":     mockIssuer,
	}
	addDeviceUIServerEnv(tgEnv, tempogateIssuer)
	for _, m := range extraTempogateEnv {
		for k, v := range m {
			tgEnv[k] = v
		}
	}
	stateVol := fmt.Sprintf("tempogate-cli-e2e-state-%d", time.Now().UnixNano())
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
			ExposedPorts:   []string{"8000/tcp"},
			Networks:       []string{netName},
			NetworkAliases: alias("tempogate"),
			WaitingFor:     wait.ForHTTP("/readyz").WithPort("8000/tcp").WithStartupTimeout(2 * time.Minute),
		},
		Started: true,
	})
	require.NoError(t, err, "tempogate serve")
	track(ctx, t, "tempogate", tempogate)

	// --- postgres + temporal-frontend (JWKS-backed default authorizer) ---
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

	// --- cliclient: headless Chrome + the tempogate binary in one container,
	// so the loopback server and the browser share a network namespace.
	cliImg, cliFrom := builtImageSource("E2E_CLICLIENT_IMAGE", "test/e2e/cliclient/Dockerfile", root)
	// The headless-shell base image's run.sh already pins
	// --remote-debugging-address=0.0.0.0 --remote-debugging-port=9223 and
	// runs socat to forward host-mapped 9222 → internal 9223; redefining
	// those here as the container Cmd appends a *second*
	// --remote-debugging-port=9222 in chrome 148+'s run.sh ($@), which
	// either makes chrome bind both ports or crash on startup. Leaving Cmd
	// empty defers to run.sh's defaults; --disable-dev-shm-usage isn't
	// needed because shared docker-shm crashes only matter to chrome's
	// renderer process under heavy DOM trees, which this test never has.
	clientC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:          cliImg,
			FromDockerfile: cliFrom,
			ExposedPorts:   []string{"9222/tcp"},
			Networks:       []string{netName},
			NetworkAliases: alias("cliclient"),
			WaitingFor: wait.ForHTTP("/json/version").WithPort("9222/tcp").
				WithStartupTimeout(2 * time.Minute),
		},
		Started: true,
	})
	require.NoError(t, err, "cliclient")
	track(ctx, t, "cliclient", clientC)

	return &cliStack{
		mockBaseURL:      mockBase,
		tempogateBaseURL: mappedHTTP(ctx, t, tempogate, "8000"),
		frontendAddr:     mappedAddr(ctx, t, temporal, "7233"),
		client:           clientC,
		chromeWS:         devtoolsWS(ctx, t, clientC),
	}
}
