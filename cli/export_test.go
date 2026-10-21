package cli

import (
	"context"
	"time"
)

// Test-only options. Living in an _test.go file keeps the PKCE-verifier and
// state generators unexported in the production API while letting the external
// cli_test package drive their failure branches deterministically.

// WithVerifierGenerator swaps the PKCE code_verifier generator. For tests.
func WithVerifierGenerator(fn func() (string, error)) Option {
	return func(f *Flow) { f.newVerifier = fn }
}

// WithStateGenerator swaps the CSRF state generator. For tests.
func WithStateGenerator(fn func() (string, error)) Option {
	return func(f *Flow) { f.newState = fn }
}

// WithDeviceSleep swaps the sleep seam used by the polling loop. Tests record
// the requested durations and return instantly so the loop is deterministic
// without elapsed wall-clock time; production code keeps the timer-backed
// defaultSleep, so the seam never leaks into the public API.
func WithDeviceSleep(fn func(ctx context.Context, d time.Duration) error) DeviceOption {
	return func(f *DeviceFlow) { f.sleep = fn }
}

// DefaultSleep re-exports the production timer-backed sleep so the external
// test package can drive its ctx-cancel and zero-duration branches without
// reaching into package internals.
var DefaultSleep = defaultSleep

// WithShutdownTimeout swaps the bound on the loopback listener's shutdown.
// For tests that prove a stalled connection cannot hold Run open.
func WithShutdownTimeout(d time.Duration) Option {
	return func(f *Flow) { f.shutdownTimeout = d }
}

// CheckIssuer exposes the issuer transport rule for a table test.
var CheckIssuer = checkIssuer
