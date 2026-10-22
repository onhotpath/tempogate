package cli_test

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/onhotpath/tempogate/cli"
)

// callbackTarget lifts the loopback redirect URI and the expected state out of
// the authorize URL the flow hands to its browser opener, so a test can play
// both the real browser and a hostile local process hitting the listener.
func callbackTarget(authURL string) (redirectURI, state string) {
	u, _ := url.Parse(authURL)
	q := u.Query()
	return q.Get("redirect_uri"), q.Get("state")
}

func hitCallback(client *http.Client, redirectURI string, q url.Values) (int, error) {
	resp, err := client.Get(redirectURI + "?" + q.Encode())
	if err != nil {
		return 0, err
	}
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

type runResult struct {
	tok cli.Token
	err error
}

func (s *LoopbackSuite) runAsync(f *cli.Flow) <-chan runResult {
	done := make(chan runResult, 1)
	go func() {
		tok, err := f.Run(context.Background())
		done <- runResult{tok: tok, err: err}
	}()
	return done
}

func (s *LoopbackSuite) await(done <-chan runResult, within time.Duration) runResult {
	select {
	case r := <-done:
		return r
	case <-time.After(within):
		s.FailNow("login did not return", "Run still blocked after %s", within)
		return runResult{}
	}
}

// A local process (or a page in the user's browser) that finds the port must
// not be able to abort the login with a forged state: the hit is answered and
// dropped, and the genuine redirect that follows still completes the login.
func (s *LoopbackSuite) TestForgedStateHitsAreIgnored() {
	client := &http.Client{Timeout: 2 * time.Second}
	forged := make(chan int, 2)
	browser := func(authURL string) error {
		redirectURI, state := callbackTarget(authURL)
		go func() {
			for _, bad := range []string{"forged-state", ""} {
				code, _ := hitCallback(client, redirectURI, url.Values{"code": {"evil"}, "state": {bad}})
				forged <- code
			}
			_, _ = hitCallback(client, redirectURI, url.Values{"code": {"auth-code-xyz"}, "state": {state}})
		}()
		return nil
	}

	r := s.await(s.runAsync(s.newFlow(cli.WithOpenBrowser(browser))), 4*time.Second)

	s.Require().NoError(r.err, "forged-state hits must not abort the login")
	s.Equal("the.jwt.token", r.tok.AccessToken)
	s.Equal(http.StatusBadRequest, <-forged)
	s.Equal(http.StatusBadRequest, <-forged)
	s.Equal("auth-code-xyz", s.issuer.gotCode(), "only the genuine code is exchanged")
}

// Duplicate callbacks after the first valid one (a browser retry, a reload,
// another tab) must neither block their handlers nor stall the listener's
// shutdown: Run returns as soon as the exchange completes.
func (s *LoopbackSuite) TestExtraCallbacksAfterSuccessDoNotBlock() {
	release := make(chan struct{})
	s.issuer.token = func(w http.ResponseWriter, r *http.Request, m *mockIssuer) {
		<-release // hold the exchange so the duplicates land while Run is still live
		happyToken(w, r, m)
	}
	client := &http.Client{Timeout: 2 * time.Second}
	extra := make(chan int, 3)
	browser := func(authURL string) error {
		redirectURI, state := callbackTarget(authURL)
		go func() {
			ok := url.Values{"code": {"auth-code-xyz"}, "state": {state}}
			_, _ = hitCallback(client, redirectURI, ok)
			for range 3 {
				code, _ := hitCallback(client, redirectURI, ok)
				extra <- code
			}
			close(release)
		}()
		return nil
	}

	r := s.await(s.runAsync(s.newFlow(cli.WithOpenBrowser(browser))), 4*time.Second)

	s.Require().NoError(r.err)
	for range 3 {
		select {
		case code := <-extra:
			s.Equal(http.StatusConflict, code, "a duplicate callback is told the login already completed")
		case <-time.After(time.Second):
			s.Fail("a duplicate callback handler blocked")
		}
	}
}

// A connection that never finishes its request keeps the server busy; Run
// must still return promptly instead of waiting on it indefinitely.
func (s *LoopbackSuite) TestShutdownIsBounded() {
	client := &http.Client{Timeout: 2 * time.Second}
	browser := func(authURL string) error {
		redirectURI, state := callbackTarget(authURL)
		go func() {
			u, _ := url.Parse(redirectURI)
			conn, err := net.Dial("tcp", u.Host)
			if err == nil {
				_, _ = conn.Write([]byte("GET /callback HTTP/1.1\r\nHost: x\r\n")) // never terminated
				s.T().Cleanup(func() { _ = conn.Close() })
			}
			_, _ = hitCallback(client, redirectURI, url.Values{"code": {"auth-code-xyz"}, "state": {state}})
		}()
		return nil
	}

	start := time.Now()
	r := s.await(s.runAsync(s.newFlow(
		cli.WithOpenBrowser(browser),
		cli.WithShutdownTimeout(100*time.Millisecond),
	)), 4*time.Second)

	s.Require().NoError(r.err)
	s.Less(time.Since(start), 2*time.Second, "a stalled connection must not hold Run past the shutdown bound")
}
