// Package observe is tempogate's own telemetry contract: the generic
// interfaces every package records its metrics through, and typed
// instruments on top of them. It imports only the standard library.
//
// A package that wants a metric declares it itself, next to the code that
// records it, from an injected Meter: nothing central changes when a metric
// is added. The telemetry package implements Meter over OpenTelemetry and
// fx injects it; a nil Meter records nothing, so a package works unchanged
// without one.
//
// A metric is declared once with its label set as a type:
//
//	type loginLabels struct{ result, reason string }
//
//	func (l loginLabels) Attrs() []observe.Attr {
//		return []observe.Attr{observe.String("result", l.result), observe.String("reason", l.reason)}
//	}
//
//	logins, err := observe.NewCounter[loginLabels](meter, "tempogate.logins",
//		observe.WithDescription("Completed sign-in callbacks by result and reason."))
//
//	logins.Inc(ctx, loginLabels{result: "success", reason: "none"})
//
// The call site passes the struct, so it cannot add, drop or misspell a
// label. Label values must come from fixed sets chosen by tempogate's code:
// never an email, a client ID, a token or raw request input, which would
// leak into the metrics backend and explode its series count.
package observe

import "context"

// Attr is one label (or attribute) of a measurement.
type Attr struct {
	Key   string
	Value string
}

func String(key, value string) Attr { return Attr{Key: key, Value: value} }

// Meter declares instruments. Names are dotted OpenTelemetry names
// ("tempogate.logins"); the exposition format decides how they are spelled
// to the backend.
type Meter interface {
	Int64Counter(name string, opts ...InstrumentOption) (Int64Counter, error)
	Float64Histogram(name string, opts ...InstrumentOption) (Float64Histogram, error)
}

type Int64Counter interface {
	Add(ctx context.Context, incr int64, attrs ...Attr)
}

type Float64Histogram interface {
	Record(ctx context.Context, value float64, attrs ...Attr)
}

// InstrumentConfig is what an instrument is declared with. Meter
// implementations read it with NewInstrumentConfig.
type InstrumentConfig struct {
	Description string
	// Unit is a UCUM unit, "s" for a duration in seconds.
	Unit string
	// Buckets are a histogram's explicit upper bounds; nil leaves the
	// implementation's default.
	Buckets []float64
}

type InstrumentOption func(*InstrumentConfig)

func WithDescription(d string) InstrumentOption {
	return func(c *InstrumentConfig) { c.Description = d }
}

func WithUnit(u string) InstrumentOption {
	return func(c *InstrumentConfig) { c.Unit = u }
}

func WithBuckets(bounds ...float64) InstrumentOption {
	return func(c *InstrumentConfig) { c.Buckets = bounds }
}

func NewInstrumentConfig(opts ...InstrumentOption) InstrumentConfig {
	var c InstrumentConfig
	for _, opt := range opts {
		opt(&c)
	}
	return c
}
