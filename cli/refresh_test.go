package cli_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	"github.com/onhotpath/tempogate/cli"
)

// refreshIssuer is a minimal /token endpoint for the refresh_token grant. hits
// counts requests so a test can prove the fast path never touched the network;
// token is overridable to drive the revoked path.
type refreshIssuer struct {
	srv   *httptest.Server
	hits  atomic.Int32
	token func(w http.ResponseWriter, gotRefresh string)
}

func newRefreshIssuer() *refreshIssuer {
	ri := &refreshIssuer{token: rotateRefresh}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		ri.hits.Add(1)
		_ = r.ParseForm()
		ri.token(w, r.Form.Get("refresh_token"))
	})
	ri.srv = httptest.NewServer(mux)
	return ri
}

func (ri *refreshIssuer) close() { ri.srv.Close() }

func rotateRefresh(w http.ResponseWriter, _ string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":  "new.jwt.token",
		"refresh_token": "r-rotated",
		"token_type":    "Bearer",
		"expires_in":    14400,
	})
}

type RefreshSuite struct {
	suite.Suite

	issuer *refreshIssuer
	path   string
	now    time.Time
}

func TestRefreshSuite(t *testing.T) {
	suite.Run(t, new(RefreshSuite))
}

func (s *RefreshSuite) SetupTest() {
	s.issuer = newRefreshIssuer()
	s.path = filepath.Join(s.T().TempDir(), "token.json")
	s.now = time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)
}

func (s *RefreshSuite) TearDownTest() {
	s.issuer.close()
}

func (s *RefreshSuite) ensureFresh() (cli.Token, error) {
	return cli.EnsureFresh(context.Background(), s.path, s.issuer.srv.URL,
		cli.WithRefreshClock(func() time.Time { return s.now }),
		cli.WithRefreshHTTPClient(s.issuer.srv.Client()),
	)
}

func (s *RefreshSuite) TestFreshTokenSkipsNetwork() {
	want := cli.Token{
		AccessToken:  "still.good",
		RefreshToken: "r-0",
		ExpiresAt:    s.now.Add(time.Hour), // well outside the 5-min skew
	}
	s.Require().NoError(cli.Save(s.path, want))

	got, err := s.ensureFresh()
	s.Require().NoError(err)
	s.Equal("still.good", got.AccessToken)
	s.Equal(int32(0), s.issuer.hits.Load(), "a fresh token must not hit the issuer")
}

func (s *RefreshSuite) TestExpiringTokenIsRefreshedAndRewritten() {
	s.Require().NoError(cli.Save(s.path, cli.Token{
		AccessToken:  "about.to.expire",
		RefreshToken: "r-old",
		ExpiresAt:    s.now.Add(2 * time.Minute), // inside the 5-min skew
	}))

	got, err := s.ensureFresh()
	s.Require().NoError(err)
	s.Equal("new.jwt.token", got.AccessToken)
	s.Equal("r-rotated", got.RefreshToken)
	s.True(s.now.Add(4 * time.Hour).Equal(got.ExpiresAt))
	s.Equal(int32(1), s.issuer.hits.Load())

	persisted, err := cli.Load(s.path)
	s.Require().NoError(err)
	s.Equal("new.jwt.token", persisted.AccessToken)
	s.Equal("r-rotated", persisted.RefreshToken, "the rotated refresh token must be written back")
}

func (s *RefreshSuite) TestRevokedRefreshFailsCleanlyWithoutClobbering() {
	original := cli.Token{
		AccessToken:  "about.to.expire",
		RefreshToken: "r-revoked",
		ExpiresAt:    s.now.Add(1 * time.Minute),
	}
	s.Require().NoError(cli.Save(s.path, original))
	s.issuer.token = func(w http.ResponseWriter, _ string) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_grant",
			"error_description": "unknown or already-used refresh token",
		})
	}

	_, err := s.ensureFresh()
	s.Require().Error(err)
	s.Contains(err.Error(), "refresh failed")
	s.Contains(err.Error(), "invalid_grant")

	kept, loadErr := cli.Load(s.path)
	s.Require().NoError(loadErr)
	s.Equal(original.RefreshToken, kept.RefreshToken, "a rejected refresh must not clobber the stored token")
}

func (s *RefreshSuite) TestRefreshWithoutRotationKeepsOldRefreshToken() {
	s.Require().NoError(cli.Save(s.path, cli.Token{
		AccessToken:  "about.to.expire",
		RefreshToken: "r-keep",
		ExpiresAt:    s.now.Add(1 * time.Minute),
	}))
	s.issuer.token = func(w http.ResponseWriter, _ string) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "new.jwt.token",
			"token_type":   "Bearer",
			"expires_in":   14400,
			// no refresh_token: a deployment that does not rotate
		})
	}

	got, err := s.ensureFresh()
	s.Require().NoError(err)
	s.Equal("new.jwt.token", got.AccessToken)
	s.Equal("r-keep", got.RefreshToken, "absent rotation must not wipe the held refresh token")

	persisted, err := cli.Load(s.path)
	s.Require().NoError(err)
	s.Equal("r-keep", persisted.RefreshToken)
}

func (s *RefreshSuite) TestRefreshSucceedsButPersistFails() {
	if os.Geteuid() == 0 {
		s.T().Skip("read-only directory permissions do not constrain root")
	}
	roDir := s.T().TempDir()
	path := filepath.Join(roDir, "token.json")
	s.Require().NoError(cli.Save(path, cli.Token{
		AccessToken:  "about.to.expire",
		RefreshToken: "r-old",
		ExpiresAt:    s.now.Add(1 * time.Minute),
	}))
	s.Require().NoError(os.Chmod(roDir, 0o500)) // readable (Load) but not writable (Save)
	defer func() { _ = os.Chmod(roDir, 0o700) }()

	_, err := cli.EnsureFresh(context.Background(), path, s.issuer.srv.URL,
		cli.WithRefreshClock(func() time.Time { return s.now }),
		cli.WithRefreshHTTPClient(s.issuer.srv.Client()),
	)
	s.Require().Error(err)
	s.Contains(err.Error(), "create temp token file", "a successful refresh that cannot be persisted must fail loudly")
	s.Equal(int32(1), s.issuer.hits.Load(), "the refresh itself did happen")
}

func (s *RefreshSuite) TestUnparseableIssuerFailsAtRequestBuild() {
	s.Require().NoError(cli.Save(s.path, cli.Token{
		AccessToken:  "about.to.expire",
		RefreshToken: "r-old",
		ExpiresAt:    s.now.Add(1 * time.Minute),
	}))

	_, err := cli.EnsureFresh(context.Background(), s.path, "http://\x7fbad",
		cli.WithRefreshClock(func() time.Time { return s.now }),
	)
	s.Require().Error(err)
	s.Contains(err.Error(), "build token request")
}

func (s *RefreshSuite) TestMissingFileIsErrNoToken() {
	_, err := s.ensureFresh()
	s.Require().Error(err)
	s.ErrorIs(err, cli.ErrNoToken)
	s.Equal(int32(0), s.issuer.hits.Load())
}

func (s *RefreshSuite) TestExpiringWithoutRefreshTokenErrors() {
	s.Require().NoError(cli.Save(s.path, cli.Token{
		AccessToken: "about.to.expire",
		ExpiresAt:   s.now.Add(1 * time.Minute),
	}))

	_, err := s.ensureFresh()
	s.Require().Error(err)
	s.Contains(err.Error(), "no refresh token")
	s.Equal(int32(0), s.issuer.hits.Load())
}
