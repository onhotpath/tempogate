package telemetry

import (
	"context"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
)

func TestSpanExporterFromEnv(t *testing.T) {
	for name, tc := range map[string]struct {
		env     map[string]string
		enabled bool
		err     string
	}{
		"unset is off":               {env: map[string]string{}},
		"none is off":                {env: map[string]string{"OTEL_TRACES_EXPORTER": "none"}},
		"otlp is on":                 {env: map[string]string{"OTEL_TRACES_EXPORTER": "otlp"}, enabled: true},
		"otlp over grpc":             {env: map[string]string{"OTEL_TRACES_EXPORTER": "otlp", "OTEL_EXPORTER_OTLP_PROTOCOL": "grpc"}, enabled: true},
		"traces protocol wins":       {env: map[string]string{"OTEL_TRACES_EXPORTER": "otlp", "OTEL_EXPORTER_OTLP_PROTOCOL": "http/json", "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL": "http/protobuf"}, enabled: true},
		"sdk disabled wins":          {env: map[string]string{"OTEL_TRACES_EXPORTER": "otlp", "OTEL_SDK_DISABLED": "true"}},
		"unsupported exporter":       {env: map[string]string{"OTEL_TRACES_EXPORTER": "zipkin"}, err: `OTEL_TRACES_EXPORTER="zipkin" is not supported`},
		"exporter lists unsupported": {env: map[string]string{"OTEL_TRACES_EXPORTER": "otlp,console"}, err: "is not supported"},
		"unsupported protocol":       {env: map[string]string{"OTEL_TRACES_EXPORTER": "otlp", "OTEL_EXPORTER_OTLP_PROTOCOL": "http/json"}, err: `protocol "http/json" is not supported`},
	} {
		t.Run(name, func(t *testing.T) {
			exp, err := spanExporterFromEnv(context.Background(), func(k string) string { return tc.env[k] })
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("err = %v, want it to contain %q", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if (exp != nil) != tc.enabled {
				t.Fatalf("exporter = %v, want enabled=%v", exp, tc.enabled)
			}
			if exp != nil {
				_ = exp.Shutdown(context.Background())
			}
		})
	}
}

func TestResourceFromEnv(t *testing.T) {
	t.Setenv("OTEL_SERVICE_NAME", "")
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "deployment.environment.name=staging")
	r, err := resourceFromEnv(context.Background(), "v1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	set := r.Set()
	for k, want := range map[attribute.Key]string{
		semconv.ServiceNameKey:        "tempogate",
		semconv.ServiceVersionKey:     "v1.2.3",
		"deployment.environment.name": "staging",
	} {
		if got, _ := set.Value(k); got.AsString() != want {
			t.Errorf("%s = %q, want %q", k, got.AsString(), want)
		}
	}

	t.Setenv("OTEL_SERVICE_NAME", "tempogate-eu")
	r, err = resourceFromEnv(context.Background(), "v1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := r.Set().Value(semconv.ServiceNameKey); got.AsString() != "tempogate-eu" {
		t.Errorf("OTEL_SERVICE_NAME must override the default, got %q", got.AsString())
	}
}

// A malformed OTEL_RESOURCE_ATTRIBUTES is refused rather than half applied.
func TestResourceFromEnvRefusesMalformedAttributes(t *testing.T) {
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "deployment.environment.name")
	_, err := resourceFromEnv(context.Background(), "v1.2.3")
	if err == nil || !strings.Contains(err.Error(), "telemetry: resource: ") {
		t.Fatalf("err = %v, want the resource error", err)
	}
}
