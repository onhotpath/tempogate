package telemetry

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/suite"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/onhotpath/tempogate/observe"
	"github.com/onhotpath/tempogate/redact"
)

type TracerSuite struct {
	suite.Suite

	spans *tracetest.InMemoryExporter
	t     observe.Tracer
}

func (s *TracerSuite) SetupTest() {
	s.spans = tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(s.spans))
	s.T().Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	s.t = tracer{t: tp.Tracer(scope)}
}

func (s *TracerSuite) byName(name string) tracetest.SpanStub {
	for _, sp := range s.spans.GetSpans() {
		if sp.Name == name {
			return sp
		}
	}
	s.FailNowf("no span", "no span named %q", name)
	return tracetest.SpanStub{}
}

func attrs(sp tracetest.SpanStub) map[string]attribute.Value {
	m := map[string]attribute.Value{}
	for _, kv := range sp.Attributes {
		m[string(kv.Key)] = kv.Value
	}
	return m
}

func (s *TracerSuite) TestRootAndChildren() {
	ctx, root := s.t.Start(context.Background(), "GET", observe.AsRoot(),
		observe.WithSpanKind(observe.SpanKindServer),
		observe.WithAttributes(observe.String("tempogate.listener", "public")))
	_, child := s.t.Start(ctx, "upstream discovery", observe.WithSpanKind(observe.SpanKindClient))
	child.End()
	root.SetName("GET /token")
	root.SetAttributes(observe.Int("http.response.status_code", 200))
	root.End()

	server := s.byName("GET /token")
	s.Equal(trace.SpanKindServer, server.SpanKind)
	s.False(server.Parent.IsValid())
	s.Equal(map[string]attribute.Value{
		"tempogate.listener":        attribute.StringValue("public"),
		"http.response.status_code": attribute.IntValue(200),
	}, attrs(server))
	s.Equal(codes.Unset, server.Status.Code)

	up := s.byName("upstream discovery")
	s.Equal(trace.SpanKindClient, up.SpanKind)
	s.Equal(server.SpanContext.SpanID(), up.Parent.SpanID())
}

// A root span starts a new trace even under another span.
func (s *TracerSuite) TestAsRootStartsANewTrace() {
	outer, a := s.t.Start(context.Background(), "a", observe.AsRoot())
	_, b := s.t.Start(outer, "b", observe.AsRoot())
	b.End()
	a.End()
	s.False(s.byName("b").Parent.IsValid())
	s.NotEqual(s.byName("a").SpanContext.TraceID(), s.byName("b").SpanContext.TraceID())
}

// Outside a trace a non-root span is not started at all.
func (s *TracerSuite) TestNoSpanOutsideATrace() {
	ctx := context.Background()
	got, sp := s.t.Start(ctx, "store reap")
	sp.Fail("db_error", errors.New("x"))
	sp.End()
	s.Equal(ctx, got)
	s.Empty(s.spans.GetSpans())
}

// A failed span carries its class and, for an error, its message.
func (s *TracerSuite) TestFailRecordsClassAndMessage() {
	ctx, root := s.t.Start(context.Background(), "r", observe.AsRoot())
	_, withErr := s.t.Start(ctx, "store save_refresh")
	withErr.Fail("db_error", errors.New("UNIQUE constraint failed"))
	withErr.End()
	root.Fail("500", nil)
	root.End()

	sp := s.byName("store save_refresh")
	s.Equal(codes.Error, sp.Status.Code)
	s.Equal("UNIQUE constraint failed", sp.Status.Description)
	s.Equal(attribute.StringValue("db_error"), attrs(sp)[attrErrorType])
	s.Require().Len(sp.Events, 1, "the error is recorded as an exception event")
	s.Equal(map[string]attribute.Value{
		"exception.type":    attribute.StringValue("*errors.errorString"),
		"exception.message": attribute.StringValue("UNIQUE constraint failed"),
	}, eventAttrs(sp.Events[0]))

	r := s.byName("r")
	s.Equal(codes.Error, r.Status.Code)
	s.Empty(r.Status.Description)
	s.Equal(attribute.StringValue("500"), attrs(r)[attrErrorType])
}

// No declared value leaves in a failed span's error, neither its status nor
// its exception event. A request's Set masks the process's values too, and
// a value declared after the failure but before the span ends is still
// masked.
func (s *TracerSuite) TestDeclaredValuesAreMaskedInErrors() {
	process := redact.NewSet()
	process.Declare(redact.Secret, "gocspx-secret")
	s.t = tracer{t: s.t.(tracer).t, redaction: process}

	req := process.Child()
	ctx := redact.NewContext(context.Background(), req)
	req.Declare(redact.Identifier, "tempogate-cli")
	ctx, root := s.t.Start(ctx, "r", observe.AsRoot())
	_, child := s.t.Start(ctx, "upstream code_exchange")
	child.Fail("error", fmt.Errorf("audience tempogate-cli, secret gocspx-secret, for %w", errors.New("bob@example.com")))
	req.Declare(redact.PII, "bob@example.com")
	child.End()
	root.End()

	up := s.byName("upstream code_exchange")
	want := "audience temp***, secret [REDACTED], for b***@example.com"
	s.Equal(want, up.Status.Description)
	s.Require().Len(up.Events, 1)
	s.Equal(attribute.StringValue(want), eventAttrs(up.Events[0])["exception.message"])
	s.Equal(attribute.StringValue("*fmt.wrapError"), eventAttrs(up.Events[0])["exception.type"],
		"the type of the error, not of its scrubbed copy")
}

// Names and attributes are constants by contract and exported as they are:
// a client that declares "/token" as its refresh token cannot mangle its
// own request's route.
func (s *TracerSuite) TestNamesAndAttributesAreNotScrubbed() {
	req := redact.NewSet()
	req.Declare(redact.Secret, "/token", "POST")
	ctx := redact.NewContext(context.Background(), req)

	_, root := s.t.Start(ctx, "POST", observe.AsRoot(), observe.WithAttributes(observe.String("http.route", "/token")))
	root.SetName("POST /token")
	root.SetAttributes(observe.String("http.request.method", "POST"))
	root.End()

	r := s.byName("POST /token")
	s.Equal(map[string]attribute.Value{
		"http.route":          attribute.StringValue("/token"),
		"http.request.method": attribute.StringValue("POST"),
	}, attrs(r))
}

// Failing again replaces the failure.
func (s *TracerSuite) TestLastFailureWins() {
	_, sp := s.t.Start(context.Background(), "r", observe.AsRoot())
	sp.Fail("timeout", errors.New("first"))
	sp.Fail("error", errors.New("second"))
	sp.End()

	r := s.byName("r")
	s.Equal("second", r.Status.Description)
	s.Equal(attribute.StringValue("error"), attrs(r)[attrErrorType])
	s.Len(r.Events, 1)
}

// Outside a request the process's Set masks.
func (s *TracerSuite) TestProcessSetOutsideARequest() {
	process := redact.NewSet()
	process.Declare(redact.Secret, "gocspx-secret")
	s.t = tracer{t: s.t.(tracer).t, redaction: process}

	_, sp := s.t.Start(context.Background(), "r", observe.AsRoot())
	sp.Fail("error", errors.New("bad gocspx-secret"))
	sp.End()
	s.Equal("bad [REDACTED]", s.byName("r").Status.Description)
}

func eventAttrs(e sdktrace.Event) map[string]attribute.Value {
	m := map[string]attribute.Value{}
	for _, kv := range e.Attributes {
		m[string(kv.Key)] = kv.Value
	}
	return m
}

// The provider has no tracer while tracing is off.
func (s *TracerSuite) TestProviderWithoutExporterHasNoTracer() {
	p, err := NewProvider()
	s.Require().NoError(err)
	s.Nil(p.Tracer())
	p, err = NewProvider(WithSpanExporter(tracetest.NewInMemoryExporter()))
	s.Require().NoError(err)
	s.NotNil(p.Tracer())
	s.Require().NoError(p.Shutdown(context.Background()))
}

func TestTracerSuite(t *testing.T) {
	suite.Run(t, new(TracerSuite))
}
