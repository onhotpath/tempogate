package telemetry

import (
	"context"
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/otlptranslator"
	"go.opentelemetry.io/otel/attribute"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	"github.com/onhotpath/tempogate/observe"
)

type providerOptions struct {
	version, commit string
}

type ProviderOption func(*providerOptions)

// WithBuildInfo labels tempogate_build_info. Defaults to "dev"/"unknown".
func WithBuildInfo(version, commit string) ProviderOption {
	return func(o *providerOptions) { o.version, o.commit = version, commit }
}

// Provider owns the OpenTelemetry SDK: the meter provider every instrument
// records into, and the Prometheus registry its exporter feeds. The registry
// is private (not prometheus.DefaultRegisterer) so tests stay isolated and a
// transitive dependency cannot add series to our scrape.
type Provider struct {
	meters *sdkmetric.MeterProvider
	reg    *prometheus.Registry
}

// NewProvider builds the meter provider with a Prometheus exporter as its
// only reader: a pull exporter, so a scrape of Handler collects on demand and
// nothing runs in the background.
func NewProvider(opts ...ProviderOption) (*Provider, error) {
	o := &providerOptions{version: "dev", commit: "unknown"}
	for _, opt := range opts {
		opt(o)
	}

	reg := prometheus.NewRegistry()
	exporter, err := otelprom.New(
		otelprom.WithRegisterer(reg),
		// The exposed names are a documented contract (docs/operations.md):
		// pin the classic Prometheus translation rather than inherit a
		// default the exporter plans to change. tempogate.logins becomes
		// tempogate_logins_total, a seconds histogram gains _seconds.
		otelprom.WithTranslationStrategy(otlptranslator.UnderscoreEscapingWithSuffixes),
		// Neither adds information to a single-binary scrape, and both would
		// change the exposition dashboards already read.
		otelprom.WithoutScopeInfo(),
		otelprom.WithoutTargetInfo(),
	)
	if err != nil {
		return nil, fmt.Errorf("telemetry: prometheus exporter: %w", err)
	}
	// The runtime collectors stay native: OpenTelemetry's runtime
	// instrumentation names its series differently, and go_* / process_*
	// are what existing dashboards and alerts use. A fresh registry refuses
	// them only over a programming error (a duplicate), hence MustRegister.
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	p := &Provider{
		meters: sdkmetric.NewMeterProvider(sdkmetric.WithReader(exporter)),
		reg:    reg,
	}
	if err := declareBuildInfo(p.meters.Meter(scope), o.version, o.commit); err != nil {
		return nil, err
	}
	return p, nil
}

// declareBuildInfo is the one instrument telemetry owns: it describes the
// process, not a feature.
func declareBuildInfo(m metric.Meter, version, commit string) error {
	attrs := metric.WithAttributes(attribute.String("version", version), attribute.String("commit", commit))
	_, err := m.Int64ObservableGauge("tempogate.build_info",
		metric.WithDescription("Always 1; labels carry the running build's version and commit."),
		metric.WithInt64Callback(func(_ context.Context, obs metric.Int64Observer) error {
			obs.Observe(1, attrs)
			return nil
		}))
	if err != nil {
		return fmt.Errorf("telemetry: build_info: %w", err)
	}
	return nil
}

// Meter declares instruments on the provider, for feature packages to
// declare their own metrics through.
func (p *Provider) Meter() observe.Meter { return meter{p.meters.Meter(scope)} }

// Handler serves every instrument in the Prometheus exposition format.
func (p *Provider) Handler() http.Handler {
	return promhttp.HandlerFor(p.reg, promhttp.HandlerOpts{})
}

// Shutdown stops the meter provider; instruments record nothing after it.
func (p *Provider) Shutdown(ctx context.Context) error {
	return p.meters.Shutdown(ctx)
}
