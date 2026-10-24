package observe_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/onhotpath/tempogate/observe"
	"github.com/onhotpath/tempogate/observe/observetest"
)

type opLabels struct{ op string }

func (l opLabels) Attrs() []observe.Attr { return []observe.Attr{observe.String("op", l.op)} }

func TestInstrumentsRecordTheirLabels(t *testing.T) {
	m := observetest.NewMeter()
	c, err := observe.NewCounter[opLabels](m, "test.calls", observe.WithDescription("Calls."))
	require.NoError(t, err)
	h, err := observe.NewHistogram[opLabels](m, "test.duration",
		observe.WithDescription("Latency."), observe.WithUnit("s"), observe.WithBuckets(.1, 1))
	require.NoError(t, err)

	ctx := context.Background()
	c.Inc(ctx, opLabels{"a"})
	h.Record(ctx, .5, opLabels{"b"})

	assert.Equal(t, []observetest.Measurement{
		{Name: "test.calls", Value: 1, Attrs: map[string]string{"op": "a"}},
		{Name: "test.duration", Value: .5, Attrs: map[string]string{"op": "b"}},
	}, m.Measurements("test.calls", "test.duration"))

	cfg, ok := m.Declared("test.duration")
	require.True(t, ok)
	assert.Equal(t, observe.InstrumentConfig{Description: "Latency.", Unit: "s", Buckets: []float64{.1, 1}}, cfg)
}

// A package built without a Meter records nothing and needs no nil checks.
func TestWithoutAMeterNothingIsRecorded(t *testing.T) {
	c, err := observe.NewCounter[opLabels](nil, "test.calls")
	require.NoError(t, err)
	h, err := observe.NewHistogram[opLabels](nil, "test.duration")
	require.NoError(t, err)

	c.Inc(context.Background(), opLabels{"a"})
	h.Record(context.Background(), 1, opLabels{"a"})
	observe.Counter[opLabels]{}.Inc(context.Background(), opLabels{"a"})
	observe.Histogram[opLabels]{}.Record(context.Background(), 1, opLabels{"a"})
}

func TestDeclarationErrorsNameTheInstrument(t *testing.T) {
	boom := errors.New("boom")
	m := observetest.FailingMeter(boom)

	_, err := observe.NewCounter[opLabels](m, "test.calls")
	require.ErrorIs(t, err, boom)
	assert.ErrorContains(t, err, "test.calls")

	_, err = observe.NewHistogram[opLabels](m, "test.duration")
	require.ErrorIs(t, err, boom)
	assert.ErrorContains(t, err, "test.duration")
}

func TestRedeclaringDifferentlyFails(t *testing.T) {
	m := observetest.NewMeter()
	_, err := observe.NewCounter[opLabels](m, "test.calls", observe.WithDescription("one"))
	require.NoError(t, err)
	_, err = observe.NewCounter[opLabels](m, "test.calls", observe.WithDescription("one"))
	require.NoError(t, err, "the same declaration twice is the same instrument")
	_, err = observe.NewCounter[opLabels](m, "test.calls", observe.WithDescription("two"))
	require.Error(t, err)
}

func TestAttrHoldsAStringOrAnInt(t *testing.T) {
	assert.Equal(t, "v", observe.String("k", "v").Value())
	assert.Equal(t, 200, observe.Int("k", 200).Value())
	assert.Equal(t, "", observe.Attr{Key: "k"}.Value(), "the zero Attr is an empty string")
}
