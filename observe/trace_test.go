package observe_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/onhotpath/tempogate/observe"
)

func TestSpanConfigCollectsItsOptions(t *testing.T) {
	assert.Equal(t, observe.SpanConfig{}, observe.NewSpanConfig(), "an internal child span by default")

	cfg := observe.NewSpanConfig(
		observe.WithSpanKind(observe.SpanKindClient),
		observe.AsRoot(),
		observe.WithAttributes(observe.String("a", "1")),
		observe.WithAttributes(observe.Int("b", 2)),
	)
	assert.Equal(t, observe.SpanConfig{
		Kind:  observe.SpanKindClient,
		Root:  true,
		Attrs: []observe.Attr{observe.String("a", "1"), observe.Int("b", 2)},
	}, cfg, "attributes accumulate across options")
}

// A caller with tracing off holds a NopSpan and uses it like any other.
func TestNopSpanAcceptsEveryCall(t *testing.T) {
	var sp observe.Span = observe.NopSpan{}
	assert.NotPanics(t, func() {
		sp.SetName("n")
		sp.SetAttributes(observe.String("a", "1"))
		sp.Fail("db_error", nil)
		sp.End()
	})
}
