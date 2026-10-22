//go:build e2e

// This file is the acceptance proof for the remote-shell story: a real
// `tempogate login --device` binary runs the RFC 8628 device authorization
// grant against a tempogate container that federates to a mock Google,
// drives the templated verification UI from the test process, persists the
// issued JWT, and that JWT authenticates a real gRPC call to a
// temporal-frontend whose default authorizer is JWKS-backed by tempogate.
//
// The verification UI is driven via plain HTTP — a chromedp.Submit on the
// /device entry form's button reliably calls form.submit() in chromedp
// v0.15.1 / headless-shell 131 but the browser refuses to navigate the
// page (verified locally with explicit Location captures between actions:
// the URL stays at the verification URI). Driving the same POST → 303 →
// authorize → mock /auth → 302 chain via net/http with a cookie jar that
// addresses tempogate by its network URL passes through the identical
// server-side handlers (the same /device_authorization, /authorize,
// /callback/google, /device/sso-callback, /device/confirm,
// /device/approve|deny endpoints a real browser would hit) and applies the
// session cookie's Path and Secure attributes as a browser would.
// chromedp is still used to confirm the verification page renders end-to-
// end in chrome before the HTTP driver takes over.
//
// Three OIDC client_ids are registered (in addition to the loopback proof's
// `tempogate-cli`): `tempogate-device` (the public CLI client),
// `tempogate-device-ui` (the confidential internal client tempogate uses to
// bounce the verification page through its own /authorize chain), plus a
// signing key for the verification-page session cookie.
//
// Negative-path coverage is table-driven: a Deny POST surfaces
// `cli: user denied`, and a `--device-poll-deadline=3s` no-driver scenario
// surfaces `cli: polling deadline exceeded`.
package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/stretchr/testify/require"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
	"go.temporal.io/api/workflowservice/v1"
	"google.golang.org/grpc/metadata"

	"github.com/onhotpath/tempogate/cli"
	"github.com/onhotpath/tempogate/oidc"
)

const (
	deviceClientID       = "tempogate-device"
	deviceUIClientID     = "tempogate-device-ui"
	deviceUIClientSecret = "e2e-device-ui-confidential-secret"

	cliDeviceTokenFile  = "/tmp/tg-device-token.json"
	cliDeviceStdoutFile = "/tmp/tempogate-device.stdout"
	cliDeviceStderrFile = "/tmp/tempogate-device.stderr"
)

// userCodeDisplayPattern matches the dashed `XXXX-XXXX` display form the CLI
// prints and the confirm page renders. Letters and digits are the RFC 8628
// §6.1 base20 + 4-digit alphabet tempogate's user-code generator uses.
var userCodeDisplayPattern = regexp.MustCompile(`[BCDFGHJKLMNPQRSTVWXZ3479]{4}-[BCDFGHJKLMNPQRSTVWXZ3479]{4}`)

// verificationURIPattern matches the verification_uri_complete the CLI prints
// on stderr after a successful POST /device_authorization. The dashed
// user_code in the query is URL-safe; the path is /device under whatever the
// tempogate issuer is.
var verificationURIPattern = regexp.MustCompile(`https?://\S+/device\?user_code=[A-Z0-9%-]+`)

func TestCLIDeviceLogin(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e: skipped in -short")
	}
	ctx := context.Background()
	st := setupCLIStack(ctx, t)

	(&stack{mockBaseURL: st.mockBaseURL}).setIdentity(t, allowedEmail, true)

	// The documented device-only registration (`tempogate-device:`) carries
	// grant types, not just "no redirect URI": the device client cannot be
	// used for the authorization-code flow, and a code-flow client cannot
	// start a device authorization.
	t.Run("grant types: device-only client is refused at /authorize and vice versa", func(t *testing.T) {
		noFollow := &http.Client{
			Timeout:       15 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
		q := url.Values{
			"response_type":         {"code"},
			"client_id":             {deviceClientID},
			"redirect_uri":          {"http://127.0.0.1:1234/callback"},
			"scope":                 {"openid email"},
			"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
			"code_challenge_method": {"S256"},
		}
		resp, err := noFollow.Get(st.tempogateBaseURL + "/authorize?" + q.Encode())
		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		require.Empty(t, resp.Header.Get("Location"))
		require.Equal(t, "unauthorized_client", decodeOAuthErrorCode(t, resp))

		resp, err = http.PostForm(st.tempogateBaseURL+oidc.DeviceAuthorizationPath,
			url.Values{"client_id": {cliClientID}, "scope": {"openid"}})
		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		require.Equal(t, "unauthorized_client", decodeOAuthErrorCode(t, resp))
	})

	t.Run("happy path: approve in the UI, JWT authenticates against temporal-frontend", func(t *testing.T) {
		loginDone := make(chan loginResult, 1)
		st.spawnDeviceLogin(ctx, t, loginDone,
			cliDeviceStdoutFile, cliDeviceStderrFile,
			"--issuer", tempogateIssuer,
			"--token-file", cliDeviceTokenFile,
			"--device-poll-deadline", "2m",
		)

		verificationURI, userCode := st.waitDevicePrompt(ctx, t, cliDeviceStderrFile)
		require.Truef(t,
			strings.HasPrefix(verificationURI, tempogateIssuer+oidc.DevicePath+"?user_code="),
			"verification_uri_complete must point at tempogate's /device with a pre-filled user_code, got %q",
			verificationURI)
		require.Regexp(t, userCodeDisplayPattern, userCode,
			"user_code must be a dashed base24 XXXX-XXXX")

		st.confirmRenders(ctx, t, verificationURI)
		st.driveDeviceDecision(ctx, t, userCode, "approve")

		select {
		case r := <-loginDone:
			require.NoError(t, r.err, "tempogate login --device exec")
			require.Equalf(t, 0, r.code,
				"tempogate login --device must exit 0; stderr:\n%s",
				st.readContainerFile(ctx, t, cliDeviceStderrFile))
		case <-time.After(3 * time.Minute):
			t.Fatal("e2e: tempogate login --device did not complete after approve")
		}

		// --- the persisted token file: 0600, a parseable tempogate JWT.
		require.Equal(t, "600", st.statMode(ctx, t, cliDeviceTokenFile),
			"the device-flow token file must be -rw------- like the loopback path")
		tok := st.readTokenFrom(ctx, t, cliDeviceTokenFile)
		require.NotEmpty(t, tok.AccessToken)
		require.NotEmpty(t, tok.RefreshToken, "device flow must persist a refresh token for `tempogate token`")
		require.True(t, tok.ExpiresAt.After(time.Now().Add(3*time.Hour)),
			"a freshly minted device-flow access token should be ~4h out, same as loopback")
		assertTempogateJWT(t, tok.AccessToken)

		// --- the JWT authenticates a real gRPC call against the JWKS-backed
		// temporal-frontend, identical contract to the loopback flow.
		client, conn := dialFrontend(t, st.frontendAddr)
		defer func() { _ = conn.Close() }()

		authed := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+tok.AccessToken)
		resp, err := client.ListNamespaces(authed, &workflowservice.ListNamespacesRequest{PageSize: 10})
		require.NoError(t, err, "device-flow JWT must pass Temporal's default ClaimMapper")
		require.NotEmpty(t, resp.GetNamespaces(), "admin token should see namespaces")

		// --- tempogate token renews a device-flow session as the client the
		// tokens were issued to (tempogate-device, not the loopback default).
		require.Equal(t, deviceClientID, tok.ClientID, "device login must persist its client_id")
		expiring := tok
		expiring.ExpiresAt = time.Now().Add(-time.Minute)
		st.writeTokenTo(ctx, t, cliDeviceTokenFile, expiring)
		refreshed := st.runTokenFrom(ctx, t, cliDeviceTokenFile)
		require.NotEqual(t, tok.AccessToken, refreshed, "an expiring device-flow token must be refreshed")
		assertTempogateJWT(t, refreshed)
		after := st.readTokenFrom(ctx, t, cliDeviceTokenFile)
		require.NotEqual(t, tok.RefreshToken, after.RefreshToken, "the refresh token must rotate on use")
		require.Equal(t, deviceClientID, after.ClientID)
	})

	t.Run("negative paths", func(t *testing.T) {
		cases := []struct {
			name             string
			extraFlags       []string
			drive            func(ctx context.Context, t *testing.T, s *cliStack, userCode string)
			wantStderrSubstr string
		}{
			{
				// User reaches the confirm page, reads the code, decides not to
				// approve. RFC 8628 §3.5 access_denied; cli surfaces it as
				// ErrUserDenied = "user denied the device authorization".
				name:       "user clicks Deny on the confirm page",
				extraFlags: []string{"--device-poll-deadline", "2m"},
				drive: func(ctx context.Context, t *testing.T, s *cliStack, userCode string) {
					s.driveDeviceDecision(ctx, t, userCode, "deny")
				},
				wantStderrSubstr: "user denied",
			},
			{
				// CLI gives up before the user ever loads the verification URL.
				// With --device-poll-deadline=3s and the server's 5s default
				// interval, the deadline trips after the very first poll; the
				// cli surfaces ErrPollDeadlineExceeded =
				// "polling deadline exceeded".
				name:             "polling deadline exceeded before user approves",
				extraFlags:       []string{"--device-poll-deadline", "3s"},
				drive:            nil,
				wantStderrSubstr: "polling deadline exceeded",
			},
		}

		for _, tc := range cases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				slug := strings.ReplaceAll(strings.Map(slugSafe, tc.name), " ", "-")
				stdout := fmt.Sprintf("/tmp/tg-device-neg-%s.stdout", slug)
				stderr := fmt.Sprintf("/tmp/tg-device-neg-%s.stderr", slug)
				tokFile := fmt.Sprintf("/tmp/tg-device-neg-%s.json", slug)

				args := append([]string{
					"--issuer", tempogateIssuer,
					"--token-file", tokFile,
				}, tc.extraFlags...)

				loginDone := make(chan loginResult, 1)
				st.spawnDeviceLogin(ctx, t, loginDone, stdout, stderr, args...)

				if tc.drive != nil {
					_, userCode := st.waitDevicePrompt(ctx, t, stderr)
					tc.drive(ctx, t, st, userCode)
				}

				select {
				case r := <-loginDone:
					require.NoError(t, r.err, "tempogate login --device exec (%s)", tc.name)
					// The cli's "command failed" diagnostic flows through
					// the silenced cobra (no stderr) and out via the zap
					// logger to stdout, while the user-facing prompt sits
					// on stderr. Check both: the substring must appear in
					// at least one of them.
					stdoutBody := st.readContainerFile(ctx, t, stdout)
					stderrBody := st.readContainerFile(ctx, t, stderr)
					require.NotEqualf(t, 0, r.code,
						"tempogate login --device must exit non-zero for %q; stdout:\n%s\nstderr:\n%s",
						tc.name, stdoutBody, stderrBody)
					require.Containsf(t, stdoutBody+stderrBody, tc.wantStderrSubstr,
						"output must mention %q for %q; stdout:\n%s\nstderr:\n%s",
						tc.wantStderrSubstr, tc.name, stdoutBody, stderrBody)
				case <-time.After(2 * time.Minute):
					t.Fatalf("e2e: tempogate login --device (%s) did not exit", tc.name)
				}
			})
		}
	})
}

// ---------- cli-side helpers ----------

// spawnDeviceLogin starts `tempogate login --device` inside the cliclient
// container with stdout / stderr redirected to files on tmpfs so the test can
// poll the human-facing prompt and assert the printed access token without
// racing the live subprocess. The Exec call blocks until the binary exits;
// the goroutine reports the exit code on done so the caller can both drive
// the verification UI and wait for the subprocess in the same select.
func (s *cliStack) spawnDeviceLogin(ctx context.Context, t *testing.T, done chan<- loginResult, stdoutPath, stderrPath string, extraArgs ...string) {
	t.Helper()
	_, _, _ = s.client.Exec(ctx,
		[]string{"sh", "-c", "rm -f " + stdoutPath + " " + stderrPath},
		tcexec.Multiplexed(),
	)
	args := append([]string{"tempogate", "login", "--device", insecureFlag}, extraArgs...)
	cmd := shellQuote(args) + " > " + stdoutPath + " 2> " + stderrPath
	go func() {
		code, _, err := s.client.Exec(ctx,
			[]string{"sh", "-c", cmd},
			tcexec.Multiplexed(),
		)
		done <- loginResult{code: code, err: err}
	}()
}

// waitDevicePrompt polls stderrPath until the CLI's RFC 8628 §3.3 prompt has
// both the verification_uri_complete and a dashed user_code visible. The
// prompt is published in one Fprintf call so a single read is normally
// enough, but the polling guards against the goroutine that spawned the
// subprocess racing the file's first write.
func (s *cliStack) waitDevicePrompt(ctx context.Context, t *testing.T, stderrPath string) (verificationURI, userCode string) {
	t.Helper()
	require.Eventually(t, func() bool {
		body := s.readContainerFile(ctx, t, stderrPath)
		uri := verificationURIPattern.FindString(body)
		code := userCodeDisplayPattern.FindString(body)
		if uri == "" || code == "" {
			return false
		}
		verificationURI = uri
		userCode = code
		return true
	}, 90*time.Second, 250*time.Millisecond,
		"tempogate login --device never printed the user_code + verification_uri_complete on stderr")
	return
}

// readContainerFile cats a file inside the cliclient container and returns
// its body. Missing files return "" — the polling helpers above use the
// empty return as their "keep waiting" signal.
func (s *cliStack) readContainerFile(ctx context.Context, t *testing.T, path string) string {
	t.Helper()
	code, r, err := s.client.Exec(ctx,
		[]string{"sh", "-c", "cat " + path + " 2>/dev/null || true"},
		tcexec.Multiplexed(),
	)
	if err != nil || code != 0 {
		return ""
	}
	b, _ := io.ReadAll(r)
	return string(b)
}

// readTokenFrom pulls the JSON token file out of the container and decodes
// it. Mirrors readToken but takes the path explicitly so multiple
// concurrent device-flow scenarios can keep separate token files inside the
// same container.
func (s *cliStack) readTokenFrom(ctx context.Context, t *testing.T, path string) cli.Token {
	t.Helper()
	rc, err := s.client.CopyFileFromContainer(ctx, path)
	require.NoError(t, err)
	defer func() { _ = rc.Close() }()
	var tok cli.Token
	require.NoError(t, json.NewDecoder(rc).Decode(&tok))
	return tok
}

// confirmRenders runs chromedp against the cliclient's headless chrome only
// to prove the verification page renders end-to-end against the deployed
// tempogate: navigating to the verification_uri_complete must produce a
// 200 with the entry form's #user_code input visible. Submitting the form
// via chromedp is unreliable in this v0.15.1 / headless-shell 131 build
// (see the file header), so the actual /device POST + bounce chain is
// driven by driveDeviceDecision via plain HTTP after this check.
func (s *cliStack) confirmRenders(ctx context.Context, t *testing.T, verificationURI string) {
	t.Helper()
	allocCtx, cancelAlloc := chromedp.NewRemoteAllocator(ctx, s.chromeWS)
	t.Cleanup(cancelAlloc)
	bctx, cancelBrowser := chromedp.NewContext(allocCtx)
	t.Cleanup(cancelBrowser)
	require.NoError(t, chromedp.Run(bctx,
		chromedp.Navigate(verificationURI),
		chromedp.WaitVisible(`#user_code`, chromedp.ByID),
	), "verification page must render with #user_code visible")
}

// driveDeviceDecision walks the RFC 8628 §3.3 verification UI through a
// cookie-jar browser client (see driveVerificationUI), so the session cookie
// is returned only where its Path and Secure attributes allow, as in a real
// browser. It returns the verification-page session cookie the jar holds.
func (s *cliStack) driveDeviceDecision(ctx context.Context, t *testing.T, userCode, decision string) *http.Cookie {
	t.Helper()
	browser := newBrowserClient(t, map[string]string{
		"tempogate:8000":  strings.TrimPrefix(s.tempogateBaseURL, "http://"),
		"mockgoogle:8080": strings.TrimPrefix(s.mockBaseURL, "http://"),
	})
	driveVerificationUI(ctx, t, browser, tempogateIssuer, userCode, decision)
	for _, c := range browser.Jar.Cookies(mustParseURL(t, tempogateIssuer+oidc.DeviceConfirmPath)) {
		if c.Name == oidc.DefaultSessionCookieName {
			return c
		}
	}
	t.Fatalf("the browser holds no %s cookie after the verification UI", oidc.DefaultSessionCookieName)
	return nil
}

// mockApproveHrefPattern extracts the relative /auth/approve URL the mock
// upstream consent screen renders inside an `<a id="approve" href="…">`.
var mockApproveHrefPattern = regexp.MustCompile(`href="(/auth/approve\?[^"]+)"`)

// csrfTokenPattern extracts the CSRF token tempogate stamps into the
// /device/confirm form as a hidden input.
var csrfTokenPattern = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

// shellQuote single-quotes each arg so the assembled `sh -c` string is safe
// for whitespace, quotes, and shell metacharacters. The args here are flag
// values the test controls (durations, paths, URLs), so the quoting is more
// a discipline than a security boundary — but doing it once here keeps the
// spawnDeviceLogin call sites free of error-prone string-concat.
func shellQuote(args []string) string {
	var b strings.Builder
	for i, a := range args {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteByte('\'')
		b.WriteString(strings.ReplaceAll(a, "'", `'\''`))
		b.WriteByte('\'')
	}
	return b.String()
}

// slugSafe maps a test-name character to a filesystem-safe stand-in. The
// negative-path subtests write their stdout/stderr/token files into /tmp
// inside the cliclient; the slug feeds the path so each scenario gets its
// own files without leaking shell metacharacters from t.Run names.
func slugSafe(r rune) rune {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-':
		return r
	case r == ' ':
		return '-'
	default:
		return -1
	}
}

func decodeOAuthErrorCode(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	var body struct {
		Error string `json:"error"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	return body.Error
}
