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

	"github.com/onhotpath/tempogate/observe"
	"github.com/onhotpath/tempogate/observe/observetest"
	"github.com/onhotpath/tempogate/telemetry"
)

func TestFailedOpIsCountedAndItsSpanCarriesTheError(t *testing.T) {
	m, tr := observetest.NewMeter(), observetest.NewTracer()
	ops, err := New(m, tr)
	require.NoError(t, err)
	ctx, root := tr.Start(context.Background(), "request", observe.AsRoot())

	boom := errors.New("boom")
	opCtx, op := ops.Start(ctx, "consume_refresh")
	require.NotEqual(t, ctx, opCtx, "the operation runs under its own span")
	require.Same(t, boom, op.Fail(boom))
	op.End()
	_, op = ops.Start(ctx, "save_refresh")
	op.End()
	root.End()

	assert.Equal(t, []observetest.Measurement{
		{Name: "tempogate.db_errors", Value: 1, Attrs: map[string]string{"op": "consume_refresh"}},
	}, m.Measurements("tempogate.db_errors"), "only the failure is counted")

	failed, ok := tr.Span("store consume_refresh")
	require.True(t, ok)
	assert.Equal(t, "request", failed.Parent.Name)
	assert.Equal(t, map[string]any{"tempogate.store.op": "consume_refresh"}, failed.Attrs)
	assert.Equal(t, "db_error", failed.ErrorType)
	assert.Same(t, boom, failed.Err)
	assert.True(t, failed.Ended)

	ok2, found := tr.Span("store save_refresh")
	require.True(t, found)
	assert.Empty(t, ok2.ErrorType)
	assert.True(t, ok2.Ended)
}

// Background work outside a request is counted but not traced.
func TestOpOutsideARequestIsNotTraced(t *testing.T) {
	m, tr := observetest.NewMeter(), observetest.NewTracer()
	ops, err := New(m, tr)
	require.NoError(t, err)

	ctx := context.Background()
	got, op := ops.Start(ctx, "reap")
	assert.Equal(t, ctx, got)
	_ = op.Fail(errors.New("boom"))
	op.End()

	assert.Empty(t, tr.Spans())
	assert.Len(t, m.Measurements("tempogate.db_errors"), 1)
}

func TestWithNeitherMeterNorTracerNothingIsRecorded(t *testing.T) {
	ops, err := New(nil, nil)
	require.NoError(t, err)
	ctx := context.Background()
	got, op := ops.Start(ctx, "probe")
	assert.Equal(t, ctx, got)
	boom := errors.New("boom")
	require.Same(t, boom, op.Fail(boom))
	op.End()
}

func TestDeclarationFailureIsReturned(t *testing.T) {
	boom := errors.New("boom")
	_, err := New(observetest.FailingMeter(boom), nil)
	require.ErrorIs(t, err, boom)
}

// The scrape of the store's metric through the real exporter, line for
// line: its name, HELP text and label are a documented contract.
func TestExpositionIsUnchanged(t *testing.T) {
	p, err := telemetry.NewProvider()
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Shutdown(context.Background()) })
	ops, err := New(p.Meter(), nil)
	require.NoError(t, err)
	_, op := ops.Start(context.Background(), "consume_refresh")
	_ = op.Fail(errors.New("boom"))
	op.End()

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
