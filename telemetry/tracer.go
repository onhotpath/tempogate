package telemetry

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
	"go.opentelemetry.io/otel/trace"

	"github.com/onhotpath/tempogate/observe"
	"github.com/onhotpath/tempogate/redact"
)

// attrErrorType is the semantic-conventions attribute a failed span's class
// goes in.
const attrErrorType = "error.type"

// tracer is an observe.Tracer over an OpenTelemetry tracer. A failed span's
// error message, the one free text a span exports, passes through the
// redact.Set of the request it belongs to, or the process's outside one, so
// no declared value leaves in it. Names and attributes are not scrubbed:
// they are constants and route templates by observe's contract, and masking
// them would let a client mangle its own spans by declaring "/token" as its
// refresh token.
type tracer struct {
	t         trace.Tracer
	redaction *redact.Set
}

func (t tracer) Start(ctx context.Context, name string, opts ...observe.SpanOption) (context.Context, observe.Span) {
	cfg := observe.NewSpanConfig(opts...)
	if !cfg.Root && !trace.SpanContextFromContext(ctx).IsValid() {
		return ctx, observe.NopSpan{}
	}
	set := redact.FromContext(ctx)
	if set == nil {
		set = t.redaction
	}
	sopts := []trace.SpanStartOption{
		trace.WithSpanKind(spanKind(cfg.Kind)),
		trace.WithAttributes(otelAttrs(cfg.Attrs)...),
	}
	if cfg.Root {
		sopts = append(sopts, trace.WithNewRoot())
	}
	ctx, s := t.t.Start(ctx, name, sopts...)
	return ctx, &span{s: s, set: set}
}

func spanKind(k observe.SpanKind) trace.SpanKind {
	switch k {
	case observe.SpanKindServer:
		return trace.SpanKindServer
	case observe.SpanKindClient:
		return trace.SpanKindClient
	default:
		return trace.SpanKindInternal
	}
}

type span struct {
	s   trace.Span
	set *redact.Set

	// A failure is held until End and scrubbed then, so a value declared
	// after the failure but before this span ends is still masked (the
	// request's span fails first and ends last). Failing again replaces
	// the failure.
	failed    bool
	errorType string
	err       error
}

func (s *span) SetName(name string) { s.s.SetName(name) }

func (s *span) SetAttributes(attrs ...observe.Attr) { s.s.SetAttributes(otelAttrs(attrs)...) }

func (s *span) Fail(errorType string, err error) {
	s.failed, s.errorType, s.err = true, errorType, err
}

func (s *span) End() {
	if s.failed {
		s.s.SetAttributes(attribute.String(attrErrorType, s.errorType))
		msg := ""
		if s.err != nil {
			msg = s.set.Scrub(s.err.Error())
			// The event RecordError writes, but with the scrubbed message.
			s.s.AddEvent(semconv.ExceptionEventName, trace.WithAttributes(
				semconv.ExceptionType(fmt.Sprintf("%T", s.err)),
				semconv.ExceptionMessage(msg),
			))
		}
		s.s.SetStatus(codes.Error, msg)
	}
	s.s.End()
}
