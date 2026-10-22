package cli_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/onhotpath/tempogate/cli"
)

func TestCheckIssuer(t *testing.T) {
	cases := []struct {
		issuer   string
		insecure bool
		ok       bool
	}{
		{"https://tempogate.example.com", false, true},
		{"https://tempogate.example.com:8443/prefix", false, true},
		{"HTTPS://tempogate.example.com", false, true},
		{"http://127.0.0.1:8000", false, true},
		{"http://127.1.2.3:8000", false, true},
		{"http://[::1]:8000", false, true},
		{"http://localhost:8000", false, true},
		{"http://LOCALHOST", false, true},
		{"http://tempogate:8000", false, false},
		{"http://tempogate.example.com", false, false},
		{"http://10.0.0.5:8000", false, false},
		{"http://[::ffff:127.0.0.1]:8000", false, true},
		{"http://localhost.evil.example", false, false},
		{"http://127.0.0.1.evil.example", false, false},
		{"http://tempogate:8000", true, true},
		{"http://tempogate.example.com", true, true},
		{"ftp://tempogate.example.com", true, false},
		{"tempogate.example.com", false, false},
		{"https://", false, false},
		{"http://\x7fbad", true, false},
	}
	for _, tc := range cases {
		err := cli.CheckIssuer(tc.issuer, tc.insecure)
		if tc.ok {
			require.NoErrorf(t, err, "%q insecure=%v", tc.issuer, tc.insecure)
			continue
		}
		require.Errorf(t, err, "%q insecure=%v", tc.issuer, tc.insecure)
	}
	require.ErrorIs(t, cli.CheckIssuer("http://tempogate:8000", false), cli.ErrInsecureIssuer)
	require.ErrorContains(t, cli.CheckIssuer("http://tempogate:8000", false), "--insecure")
}

// unreachable counts any request at all; the plain-http checks must refuse
// before a single byte (and so before any token) leaves the machine.
func unreachable(t *testing.T) (*http.Client, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	t.Cleanup(srv.Close)
	// Route every request to the local server whatever host the URL names.
	tr := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", srv.Listener.Addr().String())
	}}
	return &http.Client{Transport: tr, Timeout: 2 * time.Second}, &hits
}

const plainHTTPIssuer = "http://tempogate.internal:8000"

func TestLoginRefusesPlainHTTPIssuer(t *testing.T) {
	client, hits := unreachable(t)
	opened := false
	_, err := cli.New(
		cli.WithIssuer(plainHTTPIssuer),
		cli.WithHTTPClient(client),
		cli.WithOpenBrowser(func(string) error { opened = true; return nil }),
		cli.WithCallbackTimeout(50*time.Millisecond),
	).Run(context.Background())

	require.ErrorIs(t, err, cli.ErrInsecureIssuer)
	require.False(t, opened, "the browser must not be sent to a plain-http issuer")
	require.Zero(t, hits.Load())
}

func TestDeviceLoginRefusesPlainHTTPIssuer(t *testing.T) {
	client, hits := unreachable(t)
	_, err := cli.NewDeviceFlow(
		cli.WithDeviceIssuer(plainHTTPIssuer),
		cli.WithDeviceHTTPClient(client),
	).Run(context.Background())

	require.ErrorIs(t, err, cli.ErrInsecureIssuer)
	require.Zero(t, hits.Load())
}

func TestDeviceLoginInsecureAllowsPlainHTTPIssuer(t *testing.T) {
	client, hits := unreachable(t)
	_, err := cli.NewDeviceFlow(
		cli.WithDeviceIssuer(plainHTTPIssuer),
		cli.WithDeviceHTTPClient(client),
		cli.WithDeviceInsecure(true),
	).Run(context.Background())

	require.NotErrorIs(t, err, cli.ErrInsecureIssuer)
	require.Equal(t, int32(1), hits.Load(), "--insecure lets the device request through")
}

func TestRefreshRefusesPlainHTTPIssuer(t *testing.T) {
	client, hits := unreachable(t)
	path := filepath.Join(t.TempDir(), "token.json")
	require.NoError(t, cli.Save(path, cli.Token{
		AccessToken: "about.to.expire", RefreshToken: "r-old",
		ExpiresAt: time.Now().Add(-time.Minute), ClientID: "tempogate-cli",
	}))

	_, err := cli.EnsureFresh(context.Background(), path, plainHTTPIssuer, cli.WithRefreshHTTPClient(client))
	require.ErrorIs(t, err, cli.ErrInsecureIssuer)
	require.Zero(t, hits.Load(), "the refresh token must never be sent over plain http")

	_, err = cli.EnsureFresh(context.Background(), path, plainHTTPIssuer,
		cli.WithRefreshHTTPClient(client), cli.WithRefreshInsecure(true))
	require.NotErrorIs(t, err, cli.ErrInsecureIssuer)
	require.Equal(t, int32(1), hits.Load(), "--insecure lets the refresh through")
}

// The check runs before the fast path too, so a token file kept for a
// plain-http issuer fails now, with the fix in the message, rather than
// working until its first refresh hours later.
func TestFreshTokenStillRefusesPlainHTTPIssuer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token.json")
	require.NoError(t, cli.Save(path, cli.Token{
		AccessToken: "still.good", RefreshToken: "r-0", ExpiresAt: time.Now().Add(time.Hour),
	}))

	_, err := cli.EnsureFresh(context.Background(), path, plainHTTPIssuer)
	require.ErrorIs(t, err, cli.ErrInsecureIssuer)
}

func TestLoginInsecureAllowsPlainHTTPIssuer(t *testing.T) {
	opened := false
	_, err := cli.New(
		cli.WithIssuer(plainHTTPIssuer),
		cli.WithInsecure(true),
		cli.WithOpenBrowser(func(string) error { opened = true; return nil }),
		cli.WithCallbackTimeout(50*time.Millisecond),
	).Run(context.Background())

	require.ErrorContains(t, err, "no authorization code received")
	require.True(t, opened)
}
