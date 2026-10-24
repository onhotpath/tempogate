package observetest

import (
	"context"
	"sync"

	"github.com/onhotpath/tempogate/observe"
)

// Span is one span a Tracer started.
type Span struct {
	Name   string
	Kind   observe.SpanKind
	Parent *Span // nil for a root
	Attrs  map[string]any

	ErrorType string
	Err       error
	Ended     bool

	t *Tracer
}

// Tracer records every span it starts and follows the observe.Tracer rule:
// without AsRoot it starts a span only inside an existing one. Safe for
// concurrent use.
type Tracer struct {
	mu    sync.Mutex
	spans []*Span
}

func NewTracer() *Tracer { return &Tracer{} }

type spanKey struct{}

func (t *Tracer) Start(ctx context.Context, name string, opts ...observe.SpanOption) (context.Context, observe.Span) {
	cfg := observe.NewSpanConfig(opts...)
	parent, _ := ctx.Value(spanKey{}).(*Span)
	if cfg.Root {
		parent = nil
	} else if parent == nil {
		return ctx, observe.NopSpan{}
	}
	sp := &Span{Name: name, Kind: cfg.Kind, Parent: parent, Attrs: map[string]any{}, t: t}
	for _, a := range cfg.Attrs {
		sp.Attrs[a.Key] = a.Value()
	}
	t.mu.Lock()
	t.spans = append(t.spans, sp)
	t.mu.Unlock()
	return context.WithValue(ctx, spanKey{}, sp), sp
}

// Spans returns a snapshot of every span started, in order.
func (t *Tracer) Spans() []Span {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Span, len(t.spans))
	for i, sp := range t.spans {
		out[i] = *sp
		out[i].Attrs = make(map[string]any, len(sp.Attrs))
		for k, v := range sp.Attrs {
			out[i].Attrs[k] = v
		}
	}
	return out
}

// Span returns the first span named name.
func (t *Tracer) Span(name string) (Span, bool) {
	for _, sp := range t.Spans() {
		if sp.Name == name {
			return sp, true
		}
	}
	return Span{}, false
}

func (s *Span) SetName(name string) {
	s.t.mu.Lock()
	defer s.t.mu.Unlock()
	s.Name = name
}

func (s *Span) SetAttributes(attrs ...observe.Attr) {
	s.t.mu.Lock()
	defer s.t.mu.Unlock()
	for _, a := range attrs {
		s.Attrs[a.Key] = a.Value()
	}
}

func (s *Span) Fail(errorType string, err error) {
	s.t.mu.Lock()
	defer s.t.mu.Unlock()
	s.ErrorType, s.Err = errorType, err
}

func (s *Span) End() {
	s.t.mu.Lock()
	defer s.t.mu.Unlock()
	s.Ended = true
}
