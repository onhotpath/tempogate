package upstreamhttp_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/onhotpath/tempogate/oidc/connector/upstreamhttp"
)

// TestNewClientBoundsEveryPhase: connection setup gets at most 5s of the
// budget, and the whole call, body included, the budget itself.
func TestNewClientBoundsEveryPhase(t *testing.T) {
	for _, tc := range []struct {
		timeout, setup time.Duration
	}{
		{upstreamhttp.DefaultTimeout, 5 * time.Second},
		{2 * time.Second, 2 * time.Second},
	} {
		c := upstreamhttp.NewClient(tc.timeout)
		require.Equal(t, tc.timeout, c.Timeout)
		tr, ok := c.Transport.(*http.Transport)
		require.True(t, ok)
		require.Equal(t, tc.timeout, tr.ResponseHeaderTimeout)
		require.Equal(t, tc.setup, tr.TLSHandshakeTimeout)
		require.NotNil(t, tr.DialContext)
	}
}

func TestNewClientGivesUpOnAStalledBody(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-release
	}))
	defer srv.Close()
	defer close(release)

	resp, err := upstreamhttp.NewClient(50 * time.Millisecond).Get(srv.URL)
	if err == nil {
		_, err = resp.Body.Read(make([]byte, 1))
		_ = resp.Body.Close()
	}
	require.Error(t, err)
	require.True(t, upstreamhttp.TimedOut(context.Background(), err))
}

type netTimeout struct{}

func (netTimeout) Error() string   { return "i/o timeout" }
func (netTimeout) Timeout() bool   { return true }
func (netTimeout) Temporary() bool { return true }

func TestTimedOut(t *testing.T) {
	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	live, cancelLive := context.WithTimeout(context.Background(), time.Hour)
	defer cancelLive()

	require.True(t, upstreamhttp.TimedOut(live, fmt.Errorf("wrapped: %w", context.DeadlineExceeded)))
	require.True(t, upstreamhttp.TimedOut(expired, errors.New("flattened by a library")))
	require.True(t, upstreamhttp.TimedOut(live, fmt.Errorf("dial: %w", netTimeout{})))
	require.False(t, upstreamhttp.TimedOut(live, errors.New("connection refused")))
	require.False(t, upstreamhttp.TimedOut(context.Background(), errors.New("bad gateway")))
}
