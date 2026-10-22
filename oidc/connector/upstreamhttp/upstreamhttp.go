// Package upstreamhttp is the HTTP client every connector calls its upstream
// through, so each call is bounded the same way whatever the protocol.
package upstreamhttp

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"
)

const (
	// DefaultTimeout bounds each upstream call. Without it the only bound is
	// the browser hanging up, so a stalled upstream held callback handlers
	// open indefinitely. Identity providers answer in well under a second;
	// 10s leaves room for a slow network while still failing a login before
	// a user gives up on it. The callback's overall budget bounds a
	// connector that makes several calls.
	DefaultTimeout = 10 * time.Second

	// Connection setup gets a smaller share of the budget, so an
	// unreachable or black-holed endpoint fails fast and is not mistaken for
	// a slow response.
	dialTimeout         = 5 * time.Second
	tlsHandshakeTimeout = 5 * time.Second
)

// NewClient is the client upstream calls go through, in place of
// http.DefaultClient, which has no timeout at all. The overall Timeout also
// covers reading the body, which ResponseHeaderTimeout alone would not bound
// against an endpoint that trickles it.
func NewClient(timeout time.Duration) *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.DialContext = (&net.Dialer{Timeout: min(dialTimeout, timeout), KeepAlive: 30 * time.Second}).DialContext
	t.TLSHandshakeTimeout = min(tlsHandshakeTimeout, timeout)
	t.ResponseHeaderTimeout = timeout
	return &http.Client{Transport: t, Timeout: timeout}
}

// TimedOut reports whether a call made under callCtx failed because it ran
// out of time. Some libraries flatten errors with %v, so a call that failed
// once its deadline had passed counts as timed out whatever the error says:
// the client's own timer can fire a moment before the context's.
func TimedOut(callCtx context.Context, err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	if dl, ok := callCtx.Deadline(); ok && !time.Now().Before(dl) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
