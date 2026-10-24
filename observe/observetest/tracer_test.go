package observetest_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/onhotpath/tempogate/observe"
	"github.com/onhotpath/tempogate/observe/observetest"
)

// Like the real tracer, a span starts only inside another unless AsRoot
// begins a trace.
func TestTracerStartsSpansOnlyInsideATrace(t *testing.T) {
	tr := observetest.NewTracer()
	ctx := context.Background()

	got, sp := tr.Start(ctx, "background")
	assert.Equal(t, ctx, got)
	assert.Equal(t, observe.NopSpan{}, sp)
	assert.Empty(t, tr.Spans())

	ctx, root := tr.Start(ctx, "request", observe.AsRoot(), observe.WithSpanKind(observe.SpanKindServer))
	_, child := tr.Start(ctx, "store", observe.WithAttributes(observe.String("op", "probe"), observe.Int("rows", 2)))
	_, again := tr.Start(ctx, "second request", observe.AsRoot())
	child.End()
	again.End()
	root.End()

	spans := tr.Spans()
	require.Len(t, spans, 3)
	assert.Equal(t, "request", spans[0].Name)
	assert.Equal(t, observe.SpanKindServer, spans[0].Kind)
	assert.Nil(t, spans[0].Parent)
	assert.Equal(t, "request", spans[1].Parent.Name)
	assert.Equal(t, observe.SpanKindInternal, spans[1].Kind)
	assert.Equal(t, map[string]any{"op": "probe", "rows": 2}, spans[1].Attrs)
	assert.Nil(t, spans[2].Parent, "AsRoot ignores the span ctx carries")
	for _, sp := range spans {
		assert.True(t, sp.Ended, sp.Name)
	}
}

func TestSpanRecordsWhatTheCodeSetsOnIt(t *testing.T) {
	tr := observetest.NewTracer()
	_, sp := tr.Start(context.Background(), "GET", observe.AsRoot(), observe.WithAttributes(observe.String("a", "1")))

	boom := errors.New("boom")
	sp.SetName("GET /token")
	sp.SetAttributes(observe.String("a", "2"), observe.Int("status", 500))
	sp.Fail("500", boom)

	got, ok := tr.Span("GET /token")
	require.True(t, ok)
	assert.Equal(t, map[string]any{"a": "2", "status": 500}, got.Attrs)
	assert.Equal(t, "500", got.ErrorType)
	assert.Same(t, boom, got.Err)
	assert.False(t, got.Ended)

	_, ok = tr.Span("GET")
	assert.False(t, ok, "the span is found under its new name only")
}

// Spans hands out copies, so a test inspecting them races with nothing the
// code under test still does to its spans.
func TestSpansIsASnapshot(t *testing.T) {
	tr := observetest.NewTracer()
	_, sp := tr.Start(context.Background(), "request", observe.AsRoot(), observe.WithAttributes(observe.String("a", "1")))

	before := tr.Spans()
	before[0].Attrs["a"] = "changed by the test"
	sp.SetAttributes(observe.String("b", "2"))
	sp.End()

	assert.Equal(t, map[string]any{"a": "changed by the test"}, before[0].Attrs, "later changes do not reach a snapshot")
	assert.False(t, before[0].Ended)
	after := tr.Spans()
	assert.Equal(t, map[string]any{"a": "1", "b": "2"}, after[0].Attrs, "nor do the test's edits reach the span")
	assert.True(t, after[0].Ended)
}
