//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package cli_test

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/onhotpath/tempogate/cli"
)

// reuseDetectingToken mimics tempogate's refresh-token reuse detection: the
// first presentation of a refresh token rotates it, any later presentation of
// the same one is a replay and is refused. The delay widens the window two
// unsynchronized refreshers would both fall into.
func reuseDetectingToken(delay time.Duration) func(http.ResponseWriter, string) {
	var mu sync.Mutex
	used := map[string]bool{}
	return func(w http.ResponseWriter, presented string) {
		mu.Lock()
		replay := used[presented]
		used[presented] = true
		mu.Unlock()
		time.Sleep(delay)
		if replay {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant", "error_description": "refresh token reuse"})
			return
		}
		rotateRefresh(w, presented)
	}
}

func (s *RefreshSuite) saveExpiring() {
	s.Require().NoError(cli.Save(s.path, cli.Token{
		AccessToken:  "about.to.expire",
		RefreshToken: "r-old",
		ExpiresAt:    s.now.Add(time.Minute),
		ClientID:     "tempogate-cli",
	}))
}

// Credential helpers (tctl, the temporal CLI) may run several `tempogate
// token` at once. Without coordination each presents the same refresh token,
// which the issuer treats as a replay and answers by revoking the session.
// With the lock exactly one refreshes and the others reuse its result.
func (s *RefreshSuite) TestConcurrentRefreshesShareOneNetworkRefresh() {
	s.issuer.token = reuseDetectingToken(100 * time.Millisecond)
	s.saveExpiring()

	const n = 8
	var wg sync.WaitGroup
	toks := make([]cli.Token, n)
	errs := make([]error, n)
	for i := range n {
		wg.Go(func() { toks[i], errs[i] = s.ensureFresh() })
	}
	wg.Wait()

	for i := range n {
		s.Require().NoError(errs[i], "refresher %d", i)
		s.Equal("new.jwt.token", toks[i].AccessToken, "refresher %d", i)
	}
	s.Equal(int32(1), s.issuer.hits.Load(), "exactly one refresh reaches the issuer")
	persisted, err := cli.Load(s.path)
	s.Require().NoError(err)
	s.Equal("r-rotated", persisted.RefreshToken)
}

// holdLock takes the refresh lock the way a second tempogate process would.
func (s *RefreshSuite) holdLock() {
	f, err := os.OpenFile(s.path+".lock", os.O_RDWR|os.O_CREATE, 0o600)
	s.Require().NoError(err)
	s.Require().NoError(syscall.Flock(int(f.Fd()), syscall.LOCK_EX))
	s.T().Cleanup(func() { _ = f.Close() })
}

func (s *RefreshSuite) TestLockWaitIsBounded() {
	s.saveExpiring()
	s.holdLock()

	start := time.Now()
	_, err := cli.EnsureFresh(context.Background(), s.path, s.issuer.srv.URL,
		cli.WithRefreshClock(func() time.Time { return s.now }),
		cli.WithRefreshHTTPClient(s.issuer.srv.Client()),
		cli.WithRefreshLockTimeout(150*time.Millisecond),
	)

	s.Require().ErrorIs(err, cli.ErrRefreshLockTimeout)
	s.Contains(err.Error(), s.path+".lock", "the error names the lock file")
	s.Less(time.Since(start), 2*time.Second)
	s.Equal(int32(0), s.issuer.hits.Load(), "no refresh without the lock")
}

func (s *RefreshSuite) TestLockWaitHonoursContext() {
	s.saveExpiring()
	s.holdLock()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := cli.EnsureFresh(ctx, s.path, s.issuer.srv.URL,
		cli.WithRefreshClock(func() time.Time { return s.now }),
		cli.WithRefreshHTTPClient(s.issuer.srv.Client()),
	)

	s.Require().ErrorIs(err, context.DeadlineExceeded)
	s.Equal(int32(0), s.issuer.hits.Load())
}

// A fresh token is served without touching the lock, so a long-held lock (a
// refresh stuck on a slow network) never delays the common path.
func (s *RefreshSuite) TestFreshTokenIgnoresLock() {
	s.Require().NoError(cli.Save(s.path, cli.Token{
		AccessToken: "still.good", RefreshToken: "r-0", ExpiresAt: s.now.Add(time.Hour),
	}))
	s.holdLock()

	got, err := cli.EnsureFresh(context.Background(), s.path, s.issuer.srv.URL,
		cli.WithRefreshClock(func() time.Time { return s.now }),
		cli.WithRefreshLockTimeout(50*time.Millisecond),
	)
	s.Require().NoError(err)
	s.Equal("still.good", got.AccessToken)
}

func (s *RefreshSuite) TestUnopenableLockFailsBeforeNetwork() {
	s.saveExpiring()
	s.Require().NoError(os.Mkdir(s.path+".lock", 0o700)) // a directory cannot be opened for writing

	_, err := s.ensureFresh()
	s.Require().Error(err)
	s.Contains(err.Error(), "lock")
	s.Equal(int32(0), s.issuer.hits.Load())
}
