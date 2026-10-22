//go:build e2e

package e2e

import (
	"context"
	"crypto/rand"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
)

// logWait bounds how long a log assertion waits for a line to reach the
// container log stream.
const logWait = 10 * time.Second

// containerLogs returns everything c has logged so far. The stream lags the
// process: Docker copies its stdout asynchronously, so a line tempogate wrote
// before answering a request may not be readable yet when the test holds the
// response. Assertions on lines a request caused go through waitForLogs.
func containerLogs(ctx context.Context, t *testing.T, c testcontainers.Container) string {
	t.Helper()
	logs, err := readLogs(ctx, c)
	require.NoError(t, err)
	return logs
}

func readLogs(ctx context.Context, c testcontainers.Container) (string, error) {
	rc, err := c.Logs(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = rc.Close() }()
	b, err := io.ReadAll(rc)
	return string(b), err
}

// waitForLogs polls c's logs until they contain every want and returns that
// snapshot. A negative assertion belongs on the returned snapshot, after
// waiting for a positive marker of the same event, so it cannot pass on a
// stream that has not caught up yet.
func waitForLogs(ctx context.Context, t *testing.T, c testcontainers.Container, want ...string) string {
	t.Helper()
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		logs, err := readLogs(ctx, c)
		require.NoError(collect, err)
		for _, w := range want {
			assert.Contains(collect, logs, w)
		}
	}, logWait, 100*time.Millisecond, "the container log stream must catch up")
	// The stream only grows, so a fresh read still holds every want.
	return containerLogs(ctx, t, c)
}

// logsThrough returns tempogate's logs once they hold every line it wrote for
// requests that completed before the call, for negative assertions with no
// positive marker of their own. It requests a unique path from base and waits
// for that request's access-log line, which tempogate's single stdout orders
// after them.
func logsThrough(ctx context.Context, t *testing.T, c testcontainers.Container, base string) string {
	t.Helper()
	path := "/e2e-log-barrier/" + rand.Text()
	resp, err := http.Get(base + path)
	require.NoError(t, err)
	_ = resp.Body.Close()
	return waitForLogs(ctx, t, c, `"path": "`+path+`"`)
}
