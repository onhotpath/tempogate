//go:build e2e

// Acceptance proof that a confidential client always authenticates at /token
// (M1): the real tempogate image, with temporal-ui registered confidential,
// must not redeem that client's code on a PKCE verifier alone. Before the
// fix a stored code_challenge replaced the secret check, so anyone holding a
// leaked code and its verifier could mint a token with aud=temporal-ui.
//
// The code is obtained through the whole browser chain (tempogate
// /authorize, mock Google consent, /callback/google) with a PKCE challenge,
// exactly as an attacker who controls the verifier would. The same code is
// then redeemed with both proofs to show the rejected attempt did not burn it
// and that the legitimate path (secret via HTTP Basic, the
// golang.org/x/oauth2 default the Temporal UI uses) still works.
package e2e

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcnetwork "github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestConfidentialClientRequiresSecretWithPKCE(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e: skipped in -short")
	}
	ctx := context.Background()
	root := repoRoot(t)

	net, err := tcnetwork.New(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = net.Remove(ctx) })
	netName := net.Name

	mockImg, mockFrom := builtImageSource("E2E_MOCKGOOGLE_IMAGE", "test/e2e/mockgoogle/Dockerfile", root)
	mock, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:          mockImg,
			FromDockerfile: mockFrom,
			Env:            map[string]string{"MOCK_ISSUER": mockIssuer},
			ExposedPorts:   []string{"8080/tcp"},
			Networks:       []string{netName},
			NetworkAliases: map[string][]string{netName: {"mockgoogle"}},
			WaitingFor:     wait.ForHTTP("/healthz").WithPort("8080/tcp").WithStartupTimeout(2 * time.Minute),
		},
		Started: true,
	})
	require.NoError(t, err, "mockgoogle")
	track(ctx, t, "mockgoogle", mock)
	mockBase := mappedHTTP(ctx, t, mock, "8080")

	env := redirectTestEnv(clientID + ":" + uiCallback)
	env["OIDC_CLIENT_SECRETS"] += "," + clientID + ":" + clientSecret
	tg := startTempogateAllowingFailure(ctx, t, root, netName, "tempogate-confidential", env)
	require.Truef(t, tg.booted, "tempogate must boot; logs:\n%s", tg.logs)

	status, delivered := driveCodeFlow(t, tg.base, mockBase, clientID, uiCallback)
	require.Equal(t, http.StatusFound, status)
	require.Truef(t, strings.HasPrefix(delivered, uiCallback+"?"), "code must go to the registered URI, got %q", delivered)
	u, err := url.Parse(delivered)
	require.NoError(t, err)
	code := u.Query().Get("code")
	require.NotEmpty(t, code)

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {uiCallback},
		"code_verifier": {attackerVerifier},
	}
	httpc := &http.Client{Timeout: 15 * time.Second}

	t.Run("verifier only, no secret, is invalid_client", func(t *testing.T) {
		f := url.Values{"client_id": {clientID}}
		for k, v := range form {
			f[k] = v
		}
		resp, err := httpc.PostForm(tg.base+"/token", f)
		require.NoError(t, err)
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		require.Equal(t, "invalid_client", decodeOAuthErrorCode(t, resp))
	})

	t.Run("secret and verifier redeem the same code", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, tg.base+"/token", strings.NewReader(form.Encode()))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(clientSecret))
		resp, err := httpc.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})
}
