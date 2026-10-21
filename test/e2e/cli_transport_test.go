//go:build e2e

// Acceptance proof for the CLI transport and loopback hardening (L5) and the
// cross-process refresh lock, with the real lean CLI in the cliclient
// container against the real tempogate image:
//
//   - the CLI refuses a plain-http, non-loopback issuer (here the Docker
//     network's http://tempogate:8000) unless --insecure is passed, for the
//     loopback login, the device login and `tempogate token`;
//   - a forged-state hit on the loopback listener neither aborts nor hangs
//     the login, which the genuine redirect then completes;
//   - several `tempogate token` processes refreshing one token file at once
//     all succeed with the same token and the session survives. Without the
//     lock each presented the same refresh token, which tempogate's reuse
//     detection answers by revoking the session.
package e2e

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/stretchr/testify/require"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
)

func TestCLITransport(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e: skipped in -short")
	}
	t.Parallel()
	ctx := context.Background()
	st := setupCLIStack(ctx, t)
	(&stack{mockBaseURL: st.mockBaseURL}).setIdentity(t, allowedIdentity())

	t.Run("plain-http issuer is refused without --insecure", func(t *testing.T) {
		st.exec(ctx, t, "rm", "-f", cliAuthURLFile)
		// timeout(1) bounds a regression that would otherwise sit waiting
		// for a browser or a device approval.
		for _, args := range [][]string{
			{"timeout", "20", "tempogate", "login", "--issuer", tempogateIssuer, "--token-file", cliTokenFile},
			{"timeout", "20", "tempogate", "login", "--device", "--issuer", tempogateIssuer, "--token-file", cliTokenFile},
		} {
			code, out := st.run(ctx, t, args...)
			require.NotEqualf(t, 0, code, "%v must fail: %s", args, out)
			require.Containsf(t, out, "plain http to a non-loopback host", "%v", args)
			require.Containsf(t, out, "--insecure", "the error names the opt-in: %v", args)
		}
		code, _ := st.run(ctx, t, "test", "-e", cliAuthURLFile)
		require.NotEqual(t, 0, code, "no browser is ever opened at a plain-http issuer")
	})

	t.Run("concurrent token processes share one refresh", func(t *testing.T) {
		const n = 4
		st.login(ctx, t)
		tok := st.readToken(ctx, t)
		tok.ExpiresAt = time.Now().Add(-time.Minute)
		st.writeToken(ctx, t, tok)

		// All n start together from one shell, the way a credential helper
		// fans out, each recording its exit code and output.
		var script strings.Builder
		for i := range n {
			fmt.Fprintf(&script, "( tempogate token %s --issuer %s --token-file %s > /tmp/tok%d.out 2>&1; echo $? > /tmp/tok%d.code ) & ",
				insecureFlag, tempogateIssuer, cliTokenFile, i, i)
		}
		script.WriteString("wait")
		st.exec(ctx, t, "sh", "-c", script.String())

		var printed []string
		for i := range n {
			out := st.readContainerFile(ctx, t, fmt.Sprintf("/tmp/tok%d.out", i))
			require.Equalf(t, "0", strings.TrimSpace(st.readContainerFile(ctx, t, fmt.Sprintf("/tmp/tok%d.code", i))),
				"tempogate token #%d failed: %s", i, out)
			jwt := jwtPattern.FindString(out)
			require.NotEmptyf(t, jwt, "tempogate token #%d printed no JWT: %s", i, out)
			printed = append(printed, jwt)
		}
		after := st.readToken(ctx, t)
		for i, jwt := range printed {
			require.Equalf(t, after.AccessToken, jwt, "token #%d must print the one refreshed token", i)
		}
		require.NotEqual(t, tok.AccessToken, after.AccessToken, "the token was refreshed")
		require.NotContains(t, containerLogs(ctx, t, st.tempogate), "refresh_token_reuse",
			"no process presented an already-rotated refresh token")

		// The session is intact: the rotated refresh token renews again.
		after.ExpiresAt = time.Now().Add(-time.Minute)
		st.writeToken(ctx, t, after)
		again := st.runToken(ctx, t)
		require.NotEqual(t, after.AccessToken, again)
		assertTempogateJWT(t, again)
	})

	t.Run("forged loopback hits do not abort or hang login", func(t *testing.T) {
		st.exec(ctx, t, "rm", "-f", cliAuthURLFile, cliTokenFile)
		loginDone := make(chan loginResult, 1)
		go func() {
			code, _, err := st.client.Exec(ctx, []string{
				"tempogate", "login", insecureFlag,
				"--issuer", tempogateIssuer, "--token-file", cliTokenFile,
			}, tcexec.Multiplexed())
			loginDone <- loginResult{code: code, err: err}
		}()

		authURL := st.waitAuthURL(ctx, t)
		u, err := url.Parse(authURL)
		require.NoError(t, err)
		redirectURI := u.Query().Get("redirect_uri")

		// Another page in the same browser finds the port and fires a
		// callback with its own state, twice.
		for range 2 {
			body := st.browse(ctx, t, redirectURI+"?"+url.Values{"code": {"evil"}, "state": {"forged"}}.Encode())
			require.Contains(t, body, "State mismatch")
		}
		select {
		case r := <-loginDone:
			t.Fatalf("a forged-state hit ended the login: exit %d, %v", r.code, r.err)
		default:
		}

		st.driveConsent(ctx, t, authURL)
		select {
		case r := <-loginDone:
			require.NoError(t, r.err)
			require.Equal(t, 0, r.code, "the genuine redirect still completes the login")
		case <-time.After(time.Minute):
			t.Fatal("tempogate login did not complete after consent")
		}
		assertTempogateJWT(t, st.readToken(ctx, t).AccessToken)
	})

	t.Run("plain-http refresh is refused without --insecure", func(t *testing.T) {
		code, out := st.run(ctx, t, "tempogate", "token", "--issuer", tempogateIssuer, "--token-file", cliTokenFile)
		require.NotEqualf(t, 0, code, "token must fail: %s", out)
		require.Contains(t, out, "--insecure")
	})

}

// login runs a plain `tempogate login --insecure` to completion.
func (s *cliStack) login(ctx context.Context, t *testing.T) {
	t.Helper()
	s.exec(ctx, t, "rm", "-f", cliAuthURLFile, cliTokenFile)
	done := make(chan loginResult, 1)
	go func() {
		code, _, err := s.client.Exec(ctx, []string{
			"tempogate", "login", insecureFlag,
			"--issuer", tempogateIssuer, "--token-file", cliTokenFile,
		}, tcexec.Multiplexed())
		done <- loginResult{code: code, err: err}
	}()
	s.driveConsent(ctx, t, s.waitAuthURL(ctx, t))
	select {
	case r := <-done:
		require.NoError(t, r.err)
		require.Equal(t, 0, r.code, "tempogate login must exit 0")
	case <-time.After(time.Minute):
		t.Fatal("tempogate login did not complete after consent")
	}
}

// run executes a command in the cliclient container and returns its exit
// code and combined output.
func (s *cliStack) run(ctx context.Context, t *testing.T, args ...string) (int, string) {
	t.Helper()
	code, r, err := s.client.Exec(ctx, args, tcexec.Multiplexed())
	require.NoError(t, err)
	b, _ := io.ReadAll(r)
	return code, string(b)
}

// exec is run for commands that must succeed.
func (s *cliStack) exec(ctx context.Context, t *testing.T, args ...string) {
	t.Helper()
	code, out := s.run(ctx, t, args...)
	require.Equalf(t, 0, code, "%v: %s", args, out)
}

// browse loads rawURL in the cliclient's headless Chrome, which shares the
// CLI's network namespace and so can reach its loopback listener, and returns
// the page text.
func (s *cliStack) browse(ctx context.Context, t *testing.T, rawURL string) string {
	t.Helper()
	allocCtx, cancelAlloc := chromedp.NewRemoteAllocator(ctx, s.chromeWS)
	defer cancelAlloc()
	bctx, cancelBrowser := chromedp.NewContext(allocCtx)
	defer cancelBrowser()
	bctx, cancel := context.WithTimeout(bctx, 30*time.Second)
	defer cancel()

	var body string
	require.NoError(t, chromedp.Run(bctx,
		chromedp.Navigate(rawURL),
		chromedp.Text("body", &body, chromedp.ByQuery),
	), "browse %s", rawURL)
	return body
}
