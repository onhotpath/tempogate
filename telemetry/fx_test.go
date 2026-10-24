package telemetry

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/protobuf/proto"

	"github.com/onhotpath/tempogate/observe"
)

// collector is a minimal OTLP/HTTP trace receiver.
type collector struct {
	mu       sync.Mutex
	requests []*coltracepb.ExportTraceServiceRequest
}

func newCollector(t *testing.T) (*collector, *httptest.Server) {
	t.Helper()
	c := &collector{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/traces" {
			http.NotFound(w, r)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		req := &coltracepb.ExportTraceServiceRequest{}
		if err := proto.Unmarshal(body, req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		c.mu.Lock()
		c.requests = append(c.requests, req)
		c.mu.Unlock()
		resp, _ := proto.Marshal(&coltracepb.ExportTraceServiceResponse{})
		w.Header().Set("Content-Type", "application/x-protobuf")
		_, _ = w.Write(resp)
	}))
	t.Cleanup(srv.Close)
	return c, srv
}

// spans returns every span received, keyed by name, with the resource
// attributes of the first batch.
func (c *collector) spans() (map[string]*tracepb.Span, map[string]string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	spans, resource := map[string]*tracepb.Span{}, map[string]string{}
	for _, req := range c.requests {
		for _, rs := range req.GetResourceSpans() {
			for _, kv := range rs.GetResource().GetAttributes() {
				resource[kv.GetKey()] = kv.GetValue().GetStringValue()
			}
			for _, ss := range rs.GetScopeSpans() {
				for _, sp := range ss.GetSpans() {
					spans[sp.GetName()] = sp
				}
			}
		}
	}
	return spans, resource
}

// With OTEL_TRACES_EXPORTER=otlp the module provides a Tracer exporting
// over OTLP/HTTP to the endpoint the standard variables name, and flushes
// what is still batched when the app stops. A failed span carries its class
// and its error's message.
func TestFxExportsTracesWhenEnabled(t *testing.T) {
	c, srv := newCollector(t)
	t.Setenv("OTEL_TRACES_EXPORTER", "otlp")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", srv.URL)
	t.Setenv("OTEL_SERVICE_NAME", "")
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "")

	var tr observe.Tracer
	app := fxtest.New(t, Fx(), fx.Populate(&tr))
	app.RequireStart()
	if tr == nil {
		t.Fatal("tracing is on, yet no tracer was provided")
	}

	ctx, server := tr.Start(context.Background(), "GET /callback/{connector}",
		observe.AsRoot(), observe.WithSpanKind(observe.SpanKindServer))
	ctx, upstream := tr.Start(ctx, "upstream code_exchange", observe.WithSpanKind(observe.SpanKindClient))
	upstream.Fail("error", errors.New("oauth2: invalid_grant"))
	upstream.End()
	_, store := tr.Start(ctx, "store consume_auth_request")
	store.End()
	server.End()
	app.RequireStop()

	spans, resource := c.spans()
	if len(spans) != 3 {
		t.Fatalf("got spans %v, want the request and its two children", keys(spans))
	}
	root := spans["GET /callback/{connector}"]
	up := spans["upstream code_exchange"]
	st := spans["store consume_auth_request"]
	if root == nil || up == nil || st == nil {
		t.Fatalf("missing a span in %v", keys(spans))
	}
	if len(root.GetParentSpanId()) != 0 {
		t.Error("the server span must be the trace's root")
	}
	for _, child := range []*tracepb.Span{up, st} {
		if !bytes.Equal(child.GetTraceId(), root.GetTraceId()) {
			t.Errorf("%s is in another trace", child.GetName())
		}
	}
	if !bytes.Equal(st.GetParentSpanId(), up.GetSpanId()) {
		t.Error("the store span must be the upstream span's child")
	}
	if up.GetStatus().GetCode() != tracepb.Status_STATUS_CODE_ERROR || up.GetStatus().GetMessage() != "oauth2: invalid_grant" {
		t.Errorf("upstream status = %v", up.GetStatus())
	}
	if resource["service.name"] != "tempogate" || resource["service.version"] != "dev" {
		t.Errorf("resource = %v", resource)
	}
}

// With tracing off the module provides no Tracer at all, so consumers start
// no spans and api installs no request middleware.
func TestFxProvidesNoTracerWhileTracingIsOff(t *testing.T) {
	t.Setenv("OTEL_TRACES_EXPORTER", "")
	var p struct {
		fx.In
		Tracer observe.Tracer `optional:"true"`
	}
	fxtest.New(t, Fx(), fx.Populate(&p)).RequireStart().RequireStop()
	if p.Tracer != nil {
		t.Fatalf("got a tracer %T while tracing is off", p.Tracer)
	}
}

// A tracing setting the module cannot honour fails startup instead of
// silently running without traces.
func TestFxRefusesInvalidTracingSettings(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"unsupported exporter": {"OTEL_TRACES_EXPORTER": "zipkin"},
		"malformed resource":   {"OTEL_TRACES_EXPORTER": "otlp", "OTEL_RESOURCE_ATTRIBUTES": "deployment.environment.name"},
	} {
		t.Run(name, func(t *testing.T) {
			for k, v := range env {
				t.Setenv(k, v)
			}
			var tr observe.Tracer
			err := fx.New(Fx(), fx.Populate(&tr), fx.NopLogger).Err()
			if err == nil || !strings.Contains(err.Error(), "telemetry: ") {
				t.Fatalf("err = %v, want a telemetry error", err)
			}
		})
	}
}

// What the SDK cannot do (a collector refusing spans) reaches the app's
// logger rather than unstructured stderr.
func TestFxLogsSDKErrors(t *testing.T) {
	t.Setenv("OTEL_TRACES_EXPORTER", "")
	core, logs := observer.New(zapcore.WarnLevel)
	app := fxtest.New(t, fx.Supply(zap.New(core)), Fx(), fx.Invoke(func(*Provider) {}))
	app.RequireStart()
	defer app.RequireStop()

	otel.Handle(errors.New("export refused"))

	entries := logs.FilterMessage("opentelemetry error").All()
	if len(entries) != 1 {
		t.Fatalf("got log entries %v, want one", logs.All())
	}
	if e := entries[0]; e.LoggerName != "telemetry" || e.ContextMap()["error"] != "export refused" {
		t.Errorf("entry = %+v", e)
	}
}

func keys(m map[string]*tracepb.Span) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// blockingExporter never finishes an export until its context ends, like a
// collector behind a firewall that drops packets.
type blockingExporter struct{}

func (blockingExporter) ExportSpans(ctx context.Context, _ []sdktrace.ReadOnlySpan) error {
	<-ctx.Done()
	return ctx.Err()
}

func (blockingExporter) Shutdown(context.Context) error { return nil }

// A collector that never answers cannot hold up shutdown past the bound.
func TestShutdownIsBoundedWhenTheCollectorHangs(t *testing.T) {
	p, err := NewProvider(WithSpanExporter(blockingExporter{}))
	if err != nil {
		t.Fatal(err)
	}
	_, sp := p.Tracer().Start(context.Background(), "r", observe.AsRoot())
	sp.End()

	start := time.Now()
	err = boundedShutdown(p, 100*time.Millisecond)(context.Background())
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("shutdown took %s", took)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the deadline", err)
	}
}
