//go:build e2e

// Acceptance proof for D1 (L14), deny-by-default authorization: the
// permissions an access token carries come from OIDC_AUTHZ_RULES_<n>, and a
// person no rule grants anything to gets no code and no token at all.
//
// One stack runs mockgoogle, a restartable tempogate (rules change the way an
// operator changes them: new environment, restart, same state volume),
// postgres + temporal-frontend with the JWKS-backed default authorizer and
// default ClaimMapper, temporal-ui, and cliclient (the tempogate binary plus
// the headless Chrome its loopback login uses).
//
// The rules: alice@example.com gets ns-a:read, bob@example.com gets
// temporal-system:admin, and carol@example.com is admitted (allowed domain,
// Workspace hd) but matches no rule.
package e2e

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
	tcnetwork "github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.temporal.io/api/workflowservice/v1"

	"github.com/onhotpath/tempogate/cli"
)

const (
	authzNSA = "ns-a"
	authzNSB = "ns-b"

	aliceRule = "email:alice@example.com=ns-a:read"
	bobRule   = "email:bob@example.com=temporal-system:admin"

	carolEmail = "carol@example.com"
	bobEmail   = "bob@example.com"
)

func authzIdentity(name string) mockIdentity {
	return mockIdentity{Sub: "google-sub-" + name, Email: name + "@example.com", Verified: true, HD: hostedDomain}
}

type authzStack struct {
	cli          *cliStack
	ui           *stack // the mock's identity control and the UI's in-network URL
	uiBase       string // temporal-ui mapped to the host
	tg           *restartableTempogate
	frontendAddr string
}

// tempogateEnv is the stack's tempogate configuration with the given
// authorization settings (OIDC_AUTHZ_* keys) on top.
func authzTempogateEnv(authz map[string]string) map[string]string {
	env := map[string]string{
		"HTTP_LISTENER":               "0.0.0.0:8000",
		"STATE_SQLITE_PATH":           "/state/state.db",
		"OIDC_ISSUER":                 tempogateIssuer,
		"OIDC_ALLOW_INSECURE_ISSUER":  "true",
		"OIDC_CLIENTS":                cliClientID + ":http://127.0.0.1/callback," + deviceClientID + ":," + clientID + ":" + uiCallback,
		"OIDC_CLIENT_SECRETS":         clientID + ":" + clientSecret,
		"OIDC_ALLOWED_DOMAINS":        "example.com",
		"OIDC_ALLOWED_HOSTED_DOMAINS": hostedDomain,
		"OIDC_GOOGLE_CLIENT_ID":       "tempogate-upstream",
		"OIDC_GOOGLE_CLIENT_SECRET":   "tempogate-upstream-secret",
		"OIDC_GOOGLE_AUTH_ENDPOINT":   mockIssuer + "/auth",
		"OIDC_GOOGLE_TOKEN_ENDPOINT":  mockIssuer + "/token",
		"OIDC_GOOGLE_ISSUER_URL":      mockIssuer,
	}
	for k, v := range authz {
		env[k] = v
	}
	addDeviceUIServerEnv(env, tempogateIssuer)
	return env
}

func TestAuthzRules(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e: skipped in -short")
	}
	t.Parallel()
	ctx := context.Background()
	st := setupAuthzStack(ctx, t, map[string]string{
		"OIDC_AUTHZ_RULES_0": aliceRule,
		"OIDC_AUTHZ_RULES_1": bobRule,
	})
	client, conn := dialFrontend(t, st.frontendAddr)
	defer func() { _ = conn.Close() }()

	require.Contains(t, st.tg.logs(t), `"system_grant_rules": 1`, "the startup log counts the cluster-wide rules")

	t.Run("bob (temporal-system:admin) registers namespaces, lists them and starts anywhere", func(t *testing.T) {
		tok := st.login(ctx, t, "bob", "/tmp/tg-authz-bob.json")
		requirePermissions(t, tok.AccessToken, "temporal-system:admin")
		bob := withBearer(ctx, tok.AccessToken)

		// RegisterNamespace is a cluster admin call.
		registerNamespace(bob, t, client, authzNSA)
		registerNamespace(bob, t, client, authzNSB)
		waitForNamespace(bob, t, client, authzNSA)
		waitForNamespace(bob, t, client, authzNSB)

		resp, err := client.ListNamespaces(bob, &workflowservice.ListNamespacesRequest{PageSize: 10})
		require.NoError(t, err)
		require.NotEmpty(t, resp.GetNamespaces())
		_, err = client.StartWorkflowExecution(bob, startWorkflowReq(authzNSB))
		require.NoError(t, err, "temporal-system:admin writes to every namespace")
	})

	aliceTokenFile := "/tmp/tg-authz-alice.json"
	t.Run("alice (ns-a:read) reads ns-a and nothing else", func(t *testing.T) {
		tok := st.login(ctx, t, "alice", aliceTokenFile)
		requirePermissions(t, tok.AccessToken, "ns-a:read")
		alice := withBearer(ctx, tok.AccessToken)

		_, err := client.ListWorkflowExecutions(alice, &workflowservice.ListWorkflowExecutionsRequest{Namespace: authzNSA})
		require.NoError(t, err, "ns-a:read lists ns-a's workflows")

		_, err = client.StartWorkflowExecution(alice, startWorkflowReq(authzNSA))
		requirePermissionDenied(t, err, "read does not start workflows")
		_, err = client.ListWorkflowExecutions(alice, &workflowservice.ListWorkflowExecutionsRequest{Namespace: authzNSB})
		requirePermissionDenied(t, err, "ns-a:read grants nothing on ns-b")
		_, err = client.DescribeNamespace(alice, &workflowservice.DescribeNamespaceRequest{Namespace: authzNSB})
		requirePermissionDenied(t, err, "ns-a:read grants nothing on ns-b")
		_, err = client.ListNamespaces(alice, &workflowservice.ListNamespacesRequest{PageSize: 10})
		requirePermissionDenied(t, err, "ListNamespaces is cluster-scoped: only temporal-system grants it")
	})

	t.Run("web UI: alice sees ns-a's workflows, ns-b is a permission error", func(t *testing.T) {
		st.ui.setIdentity(t, authzIdentity("alice"))
		browser, token := st.uiSignIn(t)
		requirePermissions(t, token, "ns-a:read")
		require.Equal(t, http.StatusOK, st.uiAPIStatus(t, browser, token, "/namespaces/"+authzNSA+"/workflows"),
			"the UI lists ns-a's workflows")
		require.Equal(t, http.StatusForbidden, st.uiAPIStatus(t, browser, token, "/namespaces/"+authzNSB+"/workflows"),
			"ns-b's workflows are a permission error")
		require.Equal(t, http.StatusForbidden, st.uiAPIStatus(t, browser, token, "/namespaces"),
			"the namespace list needs a temporal-system grant (documented UI limitation)")
	})

	t.Run("carol (no rule) gets access_denied and no token from the loopback login", func(t *testing.T) {
		code, out := st.loginOutcome(ctx, t, "carol", "/tmp/tg-authz-carol.json")
		require.NotEqualf(t, 0, code, "login must fail; output:\n%s", out)
		require.Contains(t, out, "access_denied")
		require.Contains(t, out, "no Temporal access is granted to this account")
		require.False(t, st.cli.fileExists(ctx, t, "/tmp/tg-authz-carol.json"), "no token file is written")
		require.NotContains(t, st.tg.exec(t, "sessions", "list", "--email", carolEmail), carolEmail, "no session exists")
		logs := st.tg.logs(t)
		require.Contains(t, logs, "google sign-in refused: no authorization rule grants this account any Temporal permissions")
		require.Contains(t, logs, carolEmail)
	})

	t.Run("carol (no rule) gets access_denied and no token from the device login", func(t *testing.T) {
		st.ui.setIdentity(t, authzIdentity("carol"))
		const tokFile, stdout, stderr = "/tmp/tg-authz-carol-device.json", "/tmp/tg-authz-carol-device.out", "/tmp/tg-authz-carol-device.err"
		done := make(chan loginResult, 1)
		st.cli.spawnDeviceLogin(ctx, t, done, stdout, stderr,
			"--issuer", tempogateIssuer, "--token-file", tokFile, "--device-poll-deadline", "2m")
		_, userCode := st.cli.waitDevicePrompt(ctx, t, stderr)

		status, body := st.cli.driveDeviceSignIn(t, userCode)
		require.Equalf(t, http.StatusForbidden, status, "the verification page refuses carol: %s", body)
		require.Contains(t, body, "Access denied")

		select {
		case r := <-done:
			require.NoError(t, r.err)
			out := st.cli.readContainerFile(ctx, t, stdout) + st.cli.readContainerFile(ctx, t, stderr)
			require.NotEqualf(t, 0, r.code, "device login must fail; output:\n%s", out)
			require.Contains(t, out, "the device authorization was denied")
		case <-time.After(2 * time.Minute):
			t.Fatal("e2e: the denied device login did not exit")
		}
		require.False(t, st.cli.fileExists(ctx, t, tokFile), "no token file is written")
		require.NotContains(t, st.tg.exec(t, "sessions", "list", "--email", carolEmail), carolEmail)
	})

	t.Run("a changed rule takes effect at the next refresh", func(t *testing.T) {
		st.tg.start(t, authzTempogateEnv(map[string]string{
			"OIDC_AUTHZ_RULES_0": "email:alice@example.com=ns-b:write",
			"OIDC_AUTHZ_RULES_1": bobRule,
		}), false)

		refreshed := st.refresh(ctx, t, aliceTokenFile)
		requirePermissions(t, refreshed, "ns-b:write")
		alice := withBearer(ctx, refreshed)
		_, err := client.StartWorkflowExecution(alice, startWorkflowReq(authzNSB))
		require.NoError(t, err, "the refreshed token writes to ns-b")
		_, err = client.ListWorkflowExecutions(alice, &workflowservice.ListWorkflowExecutionsRequest{Namespace: authzNSA})
		requirePermissionDenied(t, err, "the refreshed token no longer reads ns-a")
	})

	t.Run("a removed rule ends the session at the next refresh", func(t *testing.T) {
		require.Contains(t, st.tg.exec(t, "sessions", "list", "--email", allowedEmail), cliClientID, "alice has a live CLI session")
		st.tg.start(t, authzTempogateEnv(map[string]string{"OIDC_AUTHZ_RULES_0": bobRule}), false)

		code, out := st.refreshOutcome(ctx, t, aliceTokenFile)
		require.NotEqualf(t, 0, code, "the refresh must fail: %s", out)
		require.Contains(t, out, "invalid_grant")
		// Her Web UI session stays listed until the UI next refreshes; the
		// CLI session that tried is gone.
		require.NotContains(t, st.tg.exec(t, "sessions", "list", "--email", allowedEmail), cliClientID,
			"the CLI session family is revoked")
		require.Contains(t, st.tg.logs(t), "refresh_authz_denied")
	})

	t.Run("authz explain answers from the same rules", func(t *testing.T) {
		out := st.tg.exec(t, "authz", "explain", "--email", bobEmail)
		require.Contains(t, out, bobRule)
		require.Contains(t, out, "temporal-system:admin")
		out = st.tg.exec(t, "authz", "explain", "--email", allowedEmail)
		require.Contains(t, out, "sign-in is denied")
	})
}

// TestAuthzLegacyDefault is the documented escape hatch: with
// OIDC_AUTHZ_DEFAULT_PERMISSIONS=temporal-system:admin every admitted person
// is cluster admin, as before rules existed, and the startup log says so.
func TestAuthzLegacyDefault(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e: skipped in -short")
	}
	t.Parallel()
	ctx := context.Background()
	st := setupAuthzStack(ctx, t, map[string]string{"OIDC_AUTHZ_DEFAULT_PERMISSIONS": "temporal-system:admin"})

	logs := st.tg.logs(t)
	require.Contains(t, logs, "WARN")
	require.Contains(t, logs, "every admitted user is cluster admin")

	tok := st.login(ctx, t, "carol", "/tmp/tg-authz-legacy.json")
	requirePermissions(t, tok.AccessToken, "temporal-system:admin")
	client, conn := dialFrontend(t, st.frontendAddr)
	defer func() { _ = conn.Close() }()
	resp, err := client.ListNamespaces(withBearer(ctx, tok.AccessToken), &workflowservice.ListNamespacesRequest{PageSize: 10})
	require.NoError(t, err, "carol, matched by no rule, is cluster admin through the default")
	require.NotEmpty(t, resp.GetNamespaces())
}

func requirePermissions(t *testing.T, accessToken string, want ...string) {
	t.Helper()
	parsed, err := jwt.ParseInsecure([]byte(accessToken))
	require.NoError(t, err)
	perms, ok := parsed.Field("permissions")
	require.True(t, ok)
	got := []string{}
	for _, p := range perms.([]any) {
		got = append(got, p.(string))
	}
	require.Equal(t, want, got)
}

// login signs name@example.com in through the loopback CLI flow and returns
// the persisted token; the login must succeed.
func (s *authzStack) login(ctx context.Context, t *testing.T, name, tokenFile string) cli.Token {
	t.Helper()
	code, out := s.loginOutcome(ctx, t, name, tokenFile)
	require.Equalf(t, 0, code, "tempogate login as %s; output:\n%s", name, out)
	return s.cli.readTokenFrom(ctx, t, tokenFile)
}

// loginOutcome runs `tempogate login` as name@example.com, approving at the
// mock consent screen, and returns the exit code and output.
func (s *authzStack) loginOutcome(ctx context.Context, t *testing.T, name, tokenFile string) (int, string) {
	t.Helper()
	s.ui.setIdentity(t, authzIdentity(name))
	_, _, err := s.cli.client.Exec(ctx, []string{"rm", "-f", cliAuthURLFile, tokenFile}, tcexec.Multiplexed())
	require.NoError(t, err)

	type outcome struct {
		code int
		out  string
		err  error
	}
	done := make(chan outcome, 1)
	go func() {
		code, r, err := s.cli.client.Exec(ctx, []string{
			"tempogate", "login", insecureFlag,
			"--issuer", tempogateIssuer, "--client-id", cliClientID, "--token-file", tokenFile,
		}, tcexec.Multiplexed())
		var b []byte
		if r != nil {
			b, _ = io.ReadAll(r)
		}
		done <- outcome{code: code, out: string(b), err: err}
	}()

	s.cli.driveConsent(ctx, t, s.cli.waitAuthURL(ctx, t))
	select {
	case o := <-done:
		require.NoError(t, o.err)
		return o.code, o.out
	case <-time.After(2 * time.Minute):
		t.Fatalf("e2e: tempogate login as %s did not exit", name)
		return 0, ""
	}
}

// refresh forces `tempogate token` to refresh tokenFile and returns the new
// access token; refreshOutcome returns what happened instead.
func (s *authzStack) refresh(ctx context.Context, t *testing.T, tokenFile string) string {
	t.Helper()
	code, out := s.refreshOutcome(ctx, t, tokenFile)
	require.Equalf(t, 0, code, "tempogate token: %s", out)
	m := jwtPattern.FindString(out)
	require.NotEmpty(t, m, "tempogate token printed no JWT: %q", out)
	return m
}

func (s *authzStack) refreshOutcome(ctx context.Context, t *testing.T, tokenFile string) (int, string) {
	t.Helper()
	tok := s.cli.readTokenFrom(ctx, t, tokenFile)
	tok.ExpiresAt = time.Now().Add(-time.Minute)
	s.cli.writeTokenTo(ctx, t, tokenFile, tok)
	code, r, err := s.cli.client.Exec(ctx,
		[]string{"tempogate", "token", insecureFlag, "--issuer", tempogateIssuer, "--token-file", tokenFile},
		tcexec.Multiplexed())
	require.NoError(t, err)
	b, _ := io.ReadAll(r)
	return code, string(b)
}

func (s *cliStack) fileExists(ctx context.Context, t *testing.T, path string) bool {
	t.Helper()
	code, _, err := s.client.Exec(ctx, []string{"test", "-e", path}, tcexec.Multiplexed())
	require.NoError(t, err)
	return code == 0
}

// driveDeviceSignIn enters userCode on the verification page and approves at
// the mock consent screen, then returns where the browser ends: the confirm
// page for a person with access, tempogate's access-denied page otherwise.
func (s *cliStack) driveDeviceSignIn(t *testing.T, userCode string) (int, string) {
	t.Helper()
	browser := newBrowserClient(t, map[string]string{
		"tempogate:8000":  strings.TrimPrefix(s.tempogateBaseURL, "http://"),
		"mockgoogle:8080": strings.TrimPrefix(s.mockBaseURL, "http://"),
	})
	resp, err := browser.PostForm(tempogateIssuer+"/device", url.Values{"user_code": {userCode}})
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	href := mockApproveHrefPattern.FindStringSubmatch(string(body))
	require.NotEmptyf(t, href, "POST /device must land on the mock consent page: %s", body)

	resp, err = browser.Get(mockIssuer + href[1])
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, _ = io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// uiSignIn signs the mock's current identity in to temporal-ui through the
// UI's own OIDC client (temporal-ui, confidential, against tempogate) and
// returns the access token ui-server handed its SPA: ui-server delivers it in
// the user<n> cookies its /auth/sso/callback sets (temporalio/ui v2.32.0
// server/server/auth/auth.go SetUser), and the SPA sends it back as the
// bearer of every /api/v1 call.
func (s *authzStack) uiSignIn(t *testing.T) (*http.Client, string) {
	t.Helper()
	browser := newBrowserClient(t, map[string]string{
		"tempogate:8000":   strings.TrimPrefix(s.tg.base, "http://"),
		"mockgoogle:8080":  strings.TrimPrefix(s.cli.mockBaseURL, "http://"),
		"temporal-ui:8080": strings.TrimPrefix(s.uiBase, "http://"),
	})
	resp, err := browser.Get(s.ui.uiInternal + "/auth/sso")
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	href := mockApproveHrefPattern.FindStringSubmatch(string(body))
	require.NotEmptyf(t, href, "the UI's sign-in must reach the mock consent page: %s", body)

	resp, err = browser.Get(mockIssuer + href[1])
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Truef(t, strings.HasPrefix(resp.Request.URL.String(), s.ui.uiInternal),
		"the sign-in must end back on the UI, got %s", resp.Request.URL)

	parts := map[string]string{}
	for _, c := range browser.Jar.Cookies(mustParseURL(t, s.ui.uiInternal+"/")) {
		if strings.HasPrefix(c.Name, "user") {
			parts[c.Name] = c.Value
		}
	}
	require.NotEmpty(t, parts, "ui-server sets the user cookies after a successful sign-in")
	var joined strings.Builder
	for i := 0; i < len(parts); i++ {
		joined.WriteString(parts[fmt.Sprintf("user%d", i)])
	}
	raw, err := base64.StdEncoding.DecodeString(joined.String())
	require.NoError(t, err)
	var user struct {
		AccessToken string `json:"AccessToken"`
	}
	require.NoError(t, json.Unmarshal(raw, &user))
	require.NotEmpty(t, user.AccessToken)
	return browser, user.AccessToken
}

// uiAPIStatus calls ui-server's /api/v1 proxy to temporal-frontend the way
// the SPA does, with the access token as bearer.
func (s *authzStack) uiAPIStatus(t *testing.T, browser *http.Client, accessToken, path string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, s.ui.uiInternal+"/api/v1"+path, http.NoBody)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := browser.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	return resp.StatusCode
}

func setupAuthzStack(ctx context.Context, t *testing.T, authz map[string]string) *authzStack {
	t.Helper()
	root := repoRoot(t)

	net, err := tcnetwork.New(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = net.Remove(ctx) })
	netName := net.Name
	alias := func(name string) map[string][]string { return map[string][]string{netName: {name}} }
	start := func(name string, req testcontainers.ContainerRequest) testcontainers.Container {
		t.Helper()
		req.Networks = []string{netName}
		req.NetworkAliases = alias(name)
		c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{ContainerRequest: req, Started: true})
		track(ctx, t, name, c)
		require.NoError(t, err, name)
		return c
	}

	mockImg, mockFrom := builtImageSource("E2E_MOCKGOOGLE_IMAGE", "test/e2e/mockgoogle/Dockerfile", root)
	mock := start("mockgoogle", testcontainers.ContainerRequest{
		Image: mockImg, FromDockerfile: mockFrom,
		Env:          map[string]string{"MOCK_ISSUER": mockIssuer},
		ExposedPorts: []string{"8080/tcp"},
		WaitingFor:   wait.ForHTTP("/healthz").WithPort("8080/tcp").WithStartupTimeout(2 * time.Minute),
	})
	mockBase := mappedHTTP(ctx, t, mock, "8080")

	tg := &restartableTempogate{ctx: ctx, owner: t, root: root, netName: netName,
		volPrefix: fmt.Sprintf("tempogate-authz-e2e-state-%s", strings.ToLower(t.Name()))}
	tg.start(t, authzTempogateEnv(authz), true)

	start("db", testcontainers.ContainerRequest{
		Image: postgresImage,
		Env:   map[string]string{"POSTGRES_USER": "temporal", "POSTGRES_PASSWORD": "temporal", "POSTGRES_DB": "temporal"},
		WaitingFor: wait.ForLog("database system is ready to accept connections").
			WithOccurrence(2).WithStartupTimeout(2 * time.Minute),
	})
	temporal := start("temporal", testcontainers.ContainerRequest{
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
		ExposedPorts: []string{"7233/tcp"},
		WaitingFor:   wait.ForLog("Temporal server started").WithStartupTimeout(4 * time.Minute),
	})
	ui := start("temporal-ui", testcontainers.ContainerRequest{
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
		ExposedPorts: []string{"8080/tcp"},
		WaitingFor:   wait.ForHTTP("/").WithPort("8080/tcp").WithStartupTimeout(2 * time.Minute),
	})
	cliImg, cliFrom := builtImageSource("E2E_CLICLIENT_IMAGE", "test/e2e/cliclient/Dockerfile", root)
	clientC := start("cliclient", testcontainers.ContainerRequest{
		Image: cliImg, FromDockerfile: cliFrom,
		ExposedPorts: []string{"9222/tcp"},
		WaitingFor:   wait.ForHTTP("/json/version").WithPort("9222/tcp").WithStartupTimeout(2 * time.Minute),
	})

	return &authzStack{
		cli: &cliStack{
			mockBaseURL:      mockBase,
			tempogateBaseURL: tg.base,
			client:           clientC,
			chromeWS:         devtoolsWS(ctx, t, clientC),
		},
		ui:           &stack{mockBaseURL: mockBase, uiInternal: "http://temporal-ui:8080"},
		uiBase:       mappedHTTP(ctx, t, ui, "8080"),
		tg:           tg,
		frontendAddr: mappedAddr(ctx, t, temporal, "7233"),
	}
}
