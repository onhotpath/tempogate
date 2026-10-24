package telemetry

import (
	"context"
	"net/http"
	"os"
	"time"

	"go.opentelemetry.io/otel"
	"go.uber.org/fx"
	"go.uber.org/zap"

	"github.com/onhotpath/tempogate/buildinfo"
	"github.com/onhotpath/tempogate/observe"
	"github.com/onhotpath/tempogate/redact"
)

type providerParams struct {
	fx.In

	Lifecycle fx.Lifecycle
	// Logger is optional so Fx builds in graphs without logging (package
	// tests). The app always provides one.
	Logger *zap.Logger `optional:"true"`
	// Redaction is the process's redact.Set; spans outside a request mask
	// its values.
	Redaction *redact.Set `optional:"true"`
}

func newProviderFx(p providerParams) (*Provider, error) {
	ctx := context.Background()
	logger := p.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	logger = logger.Named("telemetry")
	// The SDK reports what it cannot do (a collector that refuses spans, a
	// full export queue) through this global handler, which otherwise writes
	// unstructured lines to stderr.
	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) {
		logger.Warn("opentelemetry error", zap.Error(err))
	}))

	opts := []ProviderOption{WithBuildInfo(buildinfo.Version(), buildinfo.Commit()), WithRedaction(p.Redaction)}
	spans, err := spanExporterFromEnv(ctx, os.Getenv)
	if err != nil {
		return nil, err
	}
	if spans != nil {
		res, err := resourceFromEnv(ctx, buildinfo.Version())
		if err != nil {
			return nil, err
		}
		opts = append(opts, WithSpanExporter(spans), WithResource(res))
		logger.Info("tracing enabled: exporting spans over OTLP")
	}
	prov, err := NewProvider(opts...)
	if err != nil {
		return nil, err
	}
	p.Lifecycle.Append(fx.StopHook(boundedShutdown(prov, shutdownTimeout)))
	return prov, nil
}

// shutdownTimeout bounds the final span flush. The exporter waits up to
// OTEL_BSP_EXPORT_TIMEOUT (30s) per batch for a collector that does not
// answer, which would hold the process past SERVER_SHUTDOWN_TIMEOUT and
// the orchestrator's grace period; the flush is best effort, and spans still
// queued when it runs out are dropped.
const shutdownTimeout = 5 * time.Second

func boundedShutdown(p *Provider, d time.Duration) func(context.Context) error {
	return func(ctx context.Context) error {
		ctx, cancel := context.WithTimeout(ctx, d)
		defer cancel()
		return p.Shutdown(ctx)
	}
}

func newMeter(p *Provider) observe.Meter { return p.Meter() }

// newTracer is nil while tracing is off, so consumers start no spans and api
// installs no request middleware.
func newTracer(p *Provider) observe.Tracer { return p.Tracer() }

func handler(p *Provider) http.Handler { return p.Handler() }

// Fx provides the observe.Meter and observe.Tracer every feature package
// records through, and the exposition handler the serve command mounts on
// the admin listener. The consumers take them as optional, so a graph
// without this module records nothing.
func Fx() fx.Option {
	return fx.Options(
		fx.Provide(newProviderFx, newMeter, newTracer),
		fx.Provide(
			fx.Annotate(
				handler,
				fx.ResultTags(`name:"metrics_handler"`),
			),
		),
	)
}
