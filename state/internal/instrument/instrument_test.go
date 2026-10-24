package instrument

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/onhotpath/tempogate/observe/observetest"
	"github.com/onhotpath/tempogate/telemetry"
)

func TestFailCountsByOpAndReturnsTheError(t *testing.T) {
	m := observetest.NewMeter()
	ops, err := New(m)
	require.NoError(t, err)

	boom := errors.New("boom")
	require.Same(t, boom, ops.Fail(context.Background(), "consume_refresh", boom))

	assert.Equal(t, []observetest.Measurement{
		{Name: "tempogate.db_errors", Value: 1, Attrs: map[string]string{"op": "consume_refresh"}},
	}, m.Measurements("tempogate.db_errors"))
}

func TestWithoutAMeterFailOnlyReturnsTheError(t *testing.T) {
	ops, err := New(nil)
	require.NoError(t, err)
	boom := errors.New("boom")
	require.Same(t, boom, ops.Fail(context.Background(), "probe", boom))
}

func TestDeclarationFailureIsReturned(t *testing.T) {
	boom := errors.New("boom")
	_, err := New(observetest.FailingMeter(boom))
	require.ErrorIs(t, err, boom)
}

// The scrape of the store's metric through the real exporter, line for
// line: its name, HELP text and label are a documented contract.
func TestExpositionIsUnchanged(t *testing.T) {
	p, err := telemetry.NewProvider()
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Shutdown(context.Background()) })
	ops, err := New(p.Meter())
	require.NoError(t, err)
	_ = ops.Fail(context.Background(), "consume_refresh", errors.New("boom"))

	rec := httptest.NewRecorder()
	p.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", http.NoBody))
	var got []string
	for _, line := range strings.Split(rec.Body.String(), "\n") {
		if strings.Contains(line, "tempogate_db_errors") {
			got = append(got, line)
		}
	}
	assert.Equal(t, []string{
		"# HELP tempogate_db_errors_total State store operations that failed, by operation. Not-found results are not errors.",
		"# TYPE tempogate_db_errors_total counter",
		`tempogate_db_errors_total{op="consume_refresh"} 1`,
	}, got)
}
