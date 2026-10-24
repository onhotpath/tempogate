package observe

import "context"

// Tracer starts spans. Without AsRoot, Start makes a span only when ctx
// already carries one, and otherwise returns ctx unchanged with a span that
// records nothing: background work (the reaper, key reloads) gets its
// metrics but no traces of its own, which would bury the requests among
// periodic noise.
type Tracer interface {
	Start(ctx context.Context, name string, opts ...SpanOption) (context.Context, Span)
}

// Span is one timed operation in a trace.
type Span interface {
	SetName(name string)
	SetAttributes(attrs ...Attr)
	// Fail marks the span failed. errorType is a low-cardinality class
	// recorded as error.type ("timeout", "db_error", "500"); err, when not
	// nil, is recorded with its message, which the implementation masks
	// declared values in (see redact). Unlike a metric label, a span may
	// carry an error's text: it is what makes a trace worth reading. Names
	// and attributes are not masked, so they never carry an email, a client
	// ID, a token or raw request input. Failing again replaces the failure.
	Fail(errorType string, err error)
	End()
}

type SpanKind int

const (
	SpanKindInternal SpanKind = iota
	SpanKindServer
	SpanKindClient
)

// SpanConfig is what a span is started with. Tracer implementations read
// it with NewSpanConfig.
type SpanConfig struct {
	Kind  SpanKind
	Root  bool
	Attrs []Attr
}

type SpanOption func(*SpanConfig)

func WithSpanKind(k SpanKind) SpanOption {
	return func(c *SpanConfig) { c.Kind = k }
}

// AsRoot starts a new trace, whatever span ctx carries.
func AsRoot() SpanOption {
	return func(c *SpanConfig) { c.Root = true }
}

func WithAttributes(attrs ...Attr) SpanOption {
	return func(c *SpanConfig) { c.Attrs = append(c.Attrs, attrs...) }
}

func NewSpanConfig(opts ...SpanOption) SpanConfig {
	var c SpanConfig
	for _, opt := range opts {
		opt(&c)
	}
	return c
}

// NopSpan records nothing: the span of a caller whose Tracer is nil
// (tracing off), which checks for nil before building a span's name and
// options so that tracing off costs nothing.
type NopSpan struct{}

func (NopSpan) SetName(string)        {}
func (NopSpan) SetAttributes(...Attr) {}
func (NopSpan) Fail(string, error)    {}
func (NopSpan) End()                  {}
