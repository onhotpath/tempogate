//go:build e2e

// Acceptance proof that a refresh token is bound to the client it was issued
// to and that a confidential client authenticates to use it (M2): the real
// tempogate image, with temporal-ui registered confidential and
// tempogate-cli public. Before the fix the refresh grant ignored client_id
// entirely, so a temporal-ui refresh token was redeemable with
// client_id=tempogate-cli and no secret.
//
// Each refresh token is obtained through the whole browser chain (tempogate
// /authorize, mock Google consent, /callback/google, /token). Every rejected
// attempt is followed by the legitimate client refreshing the same token,
// proving a failed or cross-client attempt does not burn the real session.
package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcnetwork "github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
)

// refreshCLICallback is the loopback redirect the public CLI registers; any
// port is accepted for loopback, and the code is read off the final 302.
const refreshCLICallback = "http://127.0.0.1:43123/callback"

func TestRefreshTokenClientBinding(t *testing.T) {
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

	env := redirectTestEnv(clientID + ":" + uiCallback + "," + cliClientID + ":http://127.0.0.1/callback")
	env["OIDC_CLIENT_SECRETS"] += "," + clientID + ":" + clientSecret
	tg := startTempogateAllowingFailure(ctx, t, root, netName, "tempogate-refresh", env)
	require.Truef(t, tg.booted, "tempogate must boot; logs:\n%s", tg.logs)

	r := &refresher{t: t, base: tg.base, httpc: &http.Client{Timeout: 15 * time.Second}}

	t.Run("confidential client's refresh token", func(t *testing.T) {
		r.t = t
		rt := r.uiRefreshToken(mockBase)

		// The PoC: another (public) client presents the token with no secret.
		resp := r.post(url.Values{"client_id": {cliClientID}}, rt, "", "")
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		require.Equal(t, "invalid_grant", decodeOAuthErrorCode(t, resp))

		resp = r.post(url.Values{"client_id": {clientID}}, rt, "", "")
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode, "confidential refresh without a secret")
		require.Equal(t, "invalid_client", decodeOAuthErrorCode(t, resp))

		resp = r.post(nil, rt, clientID, "not-the-secret")
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode, "confidential refresh with a wrong secret")
		require.Equal(t, `Basic realm="tempogate"`, resp.Header.Get("WWW-Authenticate"))
		require.Equal(t, "invalid_client", decodeOAuthErrorCode(t, resp))

		// The legitimate client, authenticating as golang.org/x/oauth2 does
		// (HTTP Basic), still refreshes the same token, and the rotated one.
		next := r.refreshOK(r.post(nil, rt, clientID, clientSecret), clientID)
		r.refreshOK(r.post(url.Values{"client_id": {clientID}, "client_secret": {clientSecret}}, next, "", ""), clientID)
	})

	t.Run("public client's refresh token", func(t *testing.T) {
		r.t = t
		rt := r.cliRefreshToken(mockBase)

		// An authenticated client cannot borrow another client's token.
		resp := r.post(nil, rt, clientID, clientSecret)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		require.Equal(t, "invalid_grant", decodeOAuthErrorCode(t, resp))

		resp = r.post(nil, rt, "", "")
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode, "a public client must identify itself")
		require.Equal(t, "invalid_client", decodeOAuthErrorCode(t, resp))

		r.refreshOK(r.post(url.Values{"client_id": {cliClientID}}, rt, "", ""), cliClientID)
	})
}

type refresher struct {
	t     *testing.T
	base  string
	httpc *http.Client
}

// post sends a refresh_token grant with the extra form fields, using HTTP
// Basic when basicID is set.
func (r *refresher) post(extra url.Values, refreshToken, basicID, basicSecret string) *http.Response {
	r.t.Helper()
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}}
	for k, v := range extra {
		form[k] = v
	}
	return r.postToken(form, basicID, basicSecret)
}

func (r *refresher) postToken(form url.Values, basicID, basicSecret string) *http.Response {
	r.t.Helper()
	req, err := http.NewRequest(http.MethodPost, r.base+"/token", strings.NewReader(form.Encode()))
	require.NoError(r.t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicID != "" {
		req.SetBasicAuth(url.QueryEscape(basicID), url.QueryEscape(basicSecret))
	}
	resp, err := r.httpc.Do(req)
	require.NoError(r.t, err)
	return resp
}

// refreshOK asserts a successful token response issued to client wantAud
// (the access token's client_id, the ID token's aud) and returns the rotated
// refresh token.
func (r *refresher) refreshOK(resp *http.Response, wantAud string) string {
	r.t.Helper()
	defer func() { _ = resp.Body.Close() }()
	require.Equal(r.t, http.StatusOK, resp.StatusCode)
	var body struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
	}
	require.NoError(r.t, json.NewDecoder(resp.Body).Decode(&body))
	parsed, err := jwt.ParseInsecure([]byte(body.AccessToken))
	require.NoError(r.t, err)
	clientIDClaim, _ := parsed.Field("client_id")
	require.Equal(r.t, wantAud, clientIDClaim, "the token must stay issued to the client the refresh token was issued to")
	id, err := jwt.ParseInsecure([]byte(body.IDToken))
	require.NoError(r.t, err)
	aud, _ := id.Audience()
	require.Equal(r.t, []string{wantAud}, aud, "the ID token's aud must stay that client")
	require.NotEmpty(r.t, body.RefreshToken)
	return body.RefreshToken
}

func (r *refresher) code(mockBase, client, redirectURI string) string {
	r.t.Helper()
	status, delivered := driveCodeFlow(r.t, r.base, mockBase, client, redirectURI)
	require.Equal(r.t, http.StatusFound, status)
	u, err := url.Parse(delivered)
	require.NoError(r.t, err)
	code := u.Query().Get("code")
	require.NotEmptyf(r.t, code, "no code in %q", delivered)
	return code
}

func (r *refresher) uiRefreshToken(mockBase string) string {
	r.t.Helper()
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {r.code(mockBase, clientID, uiCallback)},
		"redirect_uri":  {uiCallback},
		"code_verifier": {attackerVerifier},
	}
	return r.refreshOK(r.postToken(form, clientID, clientSecret), clientID)
}

func (r *refresher) cliRefreshToken(mockBase string) string {
	r.t.Helper()
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {cliClientID},
		"code":          {r.code(mockBase, cliClientID, refreshCLICallback)},
		"redirect_uri":  {refreshCLICallback},
		"code_verifier": {attackerVerifier},
	}
	return r.refreshOK(r.postToken(form, "", ""), cliClientID)
}
