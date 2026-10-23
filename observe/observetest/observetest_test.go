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

func TestMeterRecordsEachInstrumentWithItsLabels(t *testing.T) {
	m := observetest.NewMeter()
	c, err := m.Int64Counter("test.calls")
	require.NoError(t, err)
	h, err := m.Float64Histogram("test.duration", observe.WithUnit("s"))
	require.NoError(t, err)

	ctx := context.Background()
	c.Add(ctx, 2, observe.String("op", "a"))
	h.Record(ctx, .5)
	c.Add(ctx, 1, observe.String("op", "b"))

	assert.Equal(t, []observetest.Measurement{
		{Name: "test.calls", Value: 2, Attrs: map[string]string{"op": "a"}},
		{Name: "test.calls", Value: 1, Attrs: map[string]string{"op": "b"}},
	}, m.Measurements("test.calls"), "only the named instrument, in order")
	assert.Len(t, m.Measurements("test.calls", "test.duration"), 3)
	assert.Empty(t, m.Measurements("test.other"))

	_, ok := m.Declared("test.other")
	assert.False(t, ok)
}

// The Meter refuses what a real one would split into two conflicting
// series: the same name declared again with other options.
func TestMeterRefusesAConflictingRedeclaration(t *testing.T) {
	declare := []observe.InstrumentOption{
		observe.WithDescription("Latency."), observe.WithUnit("s"), observe.WithBuckets(.1, 1),
	}
	for name, opts := range map[string][]observe.InstrumentOption{
		"description": {observe.WithDescription("Other."), observe.WithUnit("s"), observe.WithBuckets(.1, 1)},
		"unit":        {observe.WithDescription("Latency."), observe.WithUnit("ms"), observe.WithBuckets(.1, 1)},
		"bucket count": {
			observe.WithDescription("Latency."), observe.WithUnit("s"), observe.WithBuckets(.1),
		},
		"bucket bound": {
			observe.WithDescription("Latency."), observe.WithUnit("s"), observe.WithBuckets(.1, 2),
		},
	} {
		t.Run(name, func(t *testing.T) {
			m := observetest.NewMeter()
			_, err := m.Float64Histogram("test.duration", declare...)
			require.NoError(t, err)
			_, err = m.Float64Histogram("test.duration", declare...)
			require.NoError(t, err, "the same declaration twice is the same instrument")

			_, err = m.Float64Histogram("test.duration", opts...)
			require.Error(t, err)
			cfg, ok := m.Declared("test.duration")
			require.True(t, ok)
			assert.Equal(t, observe.NewInstrumentConfig(declare...), cfg, "the first declaration stands")
		})
	}
}

func TestFailingMeterRefusesEveryDeclaration(t *testing.T) {
	boom := errors.New("boom")
	m := observetest.FailingMeter(boom)

	_, err := m.Int64Counter("test.calls")
	require.ErrorIs(t, err, boom)
	_, err = m.Float64Histogram("test.duration")
	require.ErrorIs(t, err, boom)
	_, ok := m.Declared("test.calls")
	assert.False(t, ok)
}
