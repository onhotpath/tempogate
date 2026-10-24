package telemetry

import (
	"context"
	"fmt"
	"strings"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
)

// serviceName is service.name on every span unless OTEL_SERVICE_NAME or
// OTEL_RESOURCE_ATTRIBUTES sets another.
const serviceName = "tempogate"

// spanExporterFromEnv reads the standard OTEL_* variables. Tracing is opt-in,
// unlike the specification's default of otlp: OTEL_TRACES_EXPORTER=otlp turns
// it on, and unset or none leaves it off with no exporter built. The protocol
// is http/protobuf unless OTEL_EXPORTER_OTLP_TRACES_PROTOCOL or
// OTEL_EXPORTER_OTLP_PROTOCOL says grpc; either exporter reads its own
// OTEL_EXPORTER_OTLP_* settings (endpoint, headers, timeout, TLS).
func spanExporterFromEnv(ctx context.Context, getenv func(string) string) (sdktrace.SpanExporter, error) {
	if strings.EqualFold(strings.TrimSpace(getenv("OTEL_SDK_DISABLED")), "true") {
		return nil, nil
	}
	switch exporter := strings.TrimSpace(getenv("OTEL_TRACES_EXPORTER")); exporter {
	case "", "none":
		return nil, nil
	case "otlp":
	default:
		return nil, fmt.Errorf("telemetry: OTEL_TRACES_EXPORTER=%q is not supported; use otlp or none", exporter)
	}

	protocol := strings.TrimSpace(getenv("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL"))
	if protocol == "" {
		protocol = strings.TrimSpace(getenv("OTEL_EXPORTER_OTLP_PROTOCOL"))
	}
	var (
		exp sdktrace.SpanExporter
		err error
	)
	switch protocol {
	case "", "http/protobuf":
		exp, err = otlptracehttp.New(ctx)
	case "grpc":
		exp, err = otlptracegrpc.New(ctx)
	default:
		return nil, fmt.Errorf("telemetry: OTLP protocol %q is not supported; use http/protobuf or grpc", protocol)
	}
	if err != nil {
		return nil, fmt.Errorf("telemetry: otlp trace exporter: %w", err)
	}
	return exp, nil
}

// resourceFromEnv describes this process on every span: tempogate and its
// version, overridden by OTEL_SERVICE_NAME and OTEL_RESOURCE_ATTRIBUTES.
func resourceFromEnv(ctx context.Context, version string) (*resource.Resource, error) {
	r, err := resource.New(ctx,
		resource.WithTelemetrySDK(),
		resource.WithAttributes(semconv.ServiceName(serviceName), semconv.ServiceVersion(version)),
		// Last, so the environment wins.
		resource.WithFromEnv(),
	)
	if err != nil {
		return nil, fmt.Errorf("telemetry: resource: %w", err)
	}
	return r, nil
}
