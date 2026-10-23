package observe

import (
	"context"
	"fmt"
)

// Labels is a metric's fixed label set: one type per metric, whose Attrs
// returns the same keys every time.
type Labels interface {
	Attrs() []Attr
}

// Counter counts events labelled by L. The zero value counts nothing.
type Counter[L Labels] struct {
	c Int64Counter
}

// NewCounter declares a counter on m. A nil m returns the zero Counter.
func NewCounter[L Labels](m Meter, name string, opts ...InstrumentOption) (Counter[L], error) {
	if m == nil {
		return Counter[L]{}, nil
	}
	c, err := m.Int64Counter(name, opts...)
	if err != nil {
		return Counter[L]{}, fmt.Errorf("observe: counter %s: %w", name, err)
	}
	return Counter[L]{c: c}, nil
}

func (c Counter[L]) Inc(ctx context.Context, labels L) {
	if c.c != nil {
		c.c.Add(ctx, 1, labels.Attrs()...)
	}
}

// Histogram records a distribution of values labelled by L. The zero value
// records nothing.
type Histogram[L Labels] struct {
	h Float64Histogram
}

// NewHistogram declares a histogram on m. A nil m returns the zero
// Histogram.
func NewHistogram[L Labels](m Meter, name string, opts ...InstrumentOption) (Histogram[L], error) {
	if m == nil {
		return Histogram[L]{}, nil
	}
	h, err := m.Float64Histogram(name, opts...)
	if err != nil {
		return Histogram[L]{}, fmt.Errorf("observe: histogram %s: %w", name, err)
	}
	return Histogram[L]{h: h}, nil
}

func (h Histogram[L]) Record(ctx context.Context, value float64, labels L) {
	if h.h != nil {
		h.h.Record(ctx, value, labels.Attrs()...)
	}
}
