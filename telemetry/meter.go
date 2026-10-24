package telemetry

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/onhotpath/tempogate/observe"
)

// meter is an observe.Meter over an OpenTelemetry meter.
type meter struct {
	m metric.Meter
}

func (m meter) Int64Counter(name string, opts ...observe.InstrumentOption) (observe.Int64Counter, error) {
	cfg := observe.NewInstrumentConfig(opts...)
	c, err := m.m.Int64Counter(name, metric.WithDescription(cfg.Description), metric.WithUnit(cfg.Unit))
	if err != nil {
		return nil, err
	}
	return counter{c}, nil
}

func (m meter) Float64Histogram(name string, opts ...observe.InstrumentOption) (observe.Float64Histogram, error) {
	cfg := observe.NewInstrumentConfig(opts...)
	hopts := []metric.Float64HistogramOption{metric.WithDescription(cfg.Description), metric.WithUnit(cfg.Unit)}
	if cfg.Buckets != nil {
		hopts = append(hopts, metric.WithExplicitBucketBoundaries(cfg.Buckets...))
	}
	h, err := m.m.Float64Histogram(name, hopts...)
	if err != nil {
		return nil, err
	}
	return histogram{h}, nil
}

type counter struct{ c metric.Int64Counter }

func (c counter) Add(ctx context.Context, incr int64, attrs ...observe.Attr) {
	c.c.Add(ctx, incr, metric.WithAttributes(otelAttrs(attrs)...))
}

type histogram struct{ h metric.Float64Histogram }

func (h histogram) Record(ctx context.Context, v float64, attrs ...observe.Attr) {
	h.h.Record(ctx, v, metric.WithAttributes(otelAttrs(attrs)...))
}

func otelAttrs(attrs []observe.Attr) []attribute.KeyValue {
	kvs := make([]attribute.KeyValue, len(attrs))
	for i, a := range attrs {
		kvs[i] = attribute.String(a.Key, a.Value)
	}
	return kvs
}
