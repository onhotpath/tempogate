package servercmd

import "context"

// testWriter discards cobra's stdout/stderr so command tests assert on the
// returned error rather than rendered output.
type testWriter struct{}

func (testWriter) Write(p []byte) (int, error) { return len(p), nil }

// supply stands in for lazy in command tests: it hands run the given,
// test-built dependencies instead of building a sub-graph.
func supply[P any](p P) deps[P] {
	return func(_ context.Context, run func(P) error) error { return run(p) }
}
