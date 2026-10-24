package telemetry

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/suite"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"

	"github.com/onhotpath/tempogate/observe"
)

// The suite asserts on the scrape, not on instrument internals: the exposed
// names and labels are the contract (docs/operations.md), and the
// OpenTelemetry-to-Prometheus translation is part of what must hold it.
type ProviderSuite struct {
	suite.Suite

	p *Provider
}

func TestProviderSuite(t *testing.T) {
	suite.Run(t, new(ProviderSuite))
}

func (s *ProviderSuite) SetupTest() {
	var err error
	s.p, err = NewProvider(WithBuildInfo("v1.2.3", "abc1234"))
	s.Require().NoError(err)
}

func (s *ProviderSuite) TearDownTest() {
	s.Require().NoError(s.p.Shutdown(context.Background()))
}

type kindLabels struct{ result, reason string }

func (l kindLabels) Attrs() []observe.Attr {
	return []observe.Attr{observe.String("result", l.result), observe.String("reason", l.reason)}
}

type opLabels struct{ op string }

func (l opLabels) Attrs() []observe.Attr { return []observe.Attr{observe.String("op", l.op)} }

// A dotted counter becomes a _total series with its labels and description.
func (s *ProviderSuite) TestCounterIsATotalWithLabels() {
	c, err := observe.NewCounter[kindLabels](s.p.Meter(), "tempogate.logins",
		observe.WithDescription("Completed sign-ins."))
	s.Require().NoError(err)
	ctx := context.Background()
	c.Inc(ctx, kindLabels{"success", "none"})
	c.Inc(ctx, kindLabels{"success", "none"})
	c.Inc(ctx, kindLabels{"failure", "domain_not_allowed"})

	s.scrapeHas(
		`# HELP tempogate_logins_total Completed sign-ins.`,
		`# TYPE tempogate_logins_total counter`,
		`tempogate_logins_total{reason="none",result="success"} 2`,
		`tempogate_logins_total{reason="domain_not_allowed",result="failure"} 1`,
	)
}

// A seconds histogram keeps its unit suffix and the declared buckets.
func (s *ProviderSuite) TestHistogramKeepsUnitAndBuckets() {
	h, err := observe.NewHistogram[opLabels](s.p.Meter(), "tempogate.upstream_request.duration",
		observe.WithUnit("s"), observe.WithBuckets(.1, .25, 10))
	s.Require().NoError(err)
	ctx := context.Background()
	h.Record(ctx, .12, opLabels{"code_exchange"})
	h.Record(ctx, .08, opLabels{"code_exchange"})

	s.scrapeHas(
		`# TYPE tempogate_upstream_request_duration_seconds histogram`,
		`tempogate_upstream_request_duration_seconds_bucket{op="code_exchange",le="0.1"} 1`,
		`tempogate_upstream_request_duration_seconds_bucket{op="code_exchange",le="0.25"} 2`,
		`tempogate_upstream_request_duration_seconds_bucket{op="code_exchange",le="10"} 2`,
		`tempogate_upstream_request_duration_seconds_bucket{op="code_exchange",le="+Inf"} 2`,
		`tempogate_upstream_request_duration_seconds_count{op="code_exchange"} 2`,
	)
}

// Two packages declaring the same instrument identically share its series.
func (s *ProviderSuite) TestSameDeclarationSharesTheSeries() {
	ctx := context.Background()
	for range 2 {
		c, err := observe.NewCounter[opLabels](s.p.Meter(), "tempogate.db_errors")
		s.Require().NoError(err)
		c.Inc(ctx, opLabels{"probe"})
	}
	s.scrapeHas(`tempogate_db_errors_total{op="probe"} 2`)
}

// A name OpenTelemetry rejects fails the declaration, so the package
// declaring it fails to start instead of recording into a broken series.
func (s *ProviderSuite) TestInvalidNameFailsTheDeclaration() {
	_, err := observe.NewCounter[opLabels](s.p.Meter(), "tempogate logins")
	s.ErrorContains(err, "tempogate logins")
	_, err = observe.NewHistogram[opLabels](s.p.Meter(), "1tempogate.duration", observe.WithBuckets(.1, 1))
	s.ErrorContains(err, "1tempogate.duration")
}

func (s *ProviderSuite) TestHandlerExposesRuntimeAndBuildInfo() {
	s.scrapeHas(
		`# TYPE tempogate_build_info gauge`,
		`tempogate_build_info{commit="abc1234",version="v1.2.3"} 1`,
		"go_goroutines",
		"process_start_time_seconds",
	)
}

// The exposition carries only our series: no OpenTelemetry scope labels on
// them and no target_info, so the move to OpenTelemetry left the scrape as
// it was.
func (s *ProviderSuite) TestNoOpenTelemetryMetadataInScrape() {
	c, err := observe.NewCounter[opLabels](s.p.Meter(), "tempogate.db_errors")
	s.Require().NoError(err)
	c.Inc(context.Background(), opLabels{"probe"})

	body := s.scrape()
	s.Contains(body, "tempogate_db_errors_total")
	s.NotContains(body, "otel_scope_")
	s.NotContains(body, "target_info")
}

// refusingMeter refuses to declare a gauge.
type refusingMeter struct {
	noop.Meter
	err error
}

func (m refusingMeter) Int64ObservableGauge(string, ...metric.Int64ObservableGaugeOption) (metric.Int64ObservableGauge, error) {
	return nil, m.err
}

func (s *ProviderSuite) TestBuildInfoDeclarationErrorIsReported() {
	boom := errors.New("boom")
	err := declareBuildInfo(refusingMeter{err: boom}, "v1.2.3", "abc1234")
	s.ErrorIs(err, boom)
	s.ErrorContains(err, "build_info")
}

func (s *ProviderSuite) scrapeHas(want ...string) {
	body := s.scrape()
	for _, w := range want {
		s.Contains(body, w)
	}
}

func (s *ProviderSuite) scrape() string {
	return scrape(s.T(), s.p.Handler())
}

func scrape(t *testing.T, h http.Handler) string {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", http.NoBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("scrape: status %d", rec.Code)
	}
	b, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Fatalf("scrape: %v", err)
	}
	return string(b)
}

// The fx module hands consumers a Meter and the handler that exposes what
// they record, and shuts the provider down with the app.
func TestFxProvidesMeterAndHandler(t *testing.T) {
	var p struct {
		fx.In
		Meter   observe.Meter
		Handler http.Handler `name:"metrics_handler"`
	}
	app := fxtest.New(t, Fx(), fx.Populate(&p))
	app.RequireStart()

	c, err := observe.NewCounter[opLabels](p.Meter, "tempogate.db_errors")
	if err != nil {
		t.Fatal(err)
	}
	c.Inc(context.Background(), opLabels{"probe"})

	body := scrape(t, p.Handler)
	for _, want := range []string{
		`tempogate_db_errors_total{op="probe"} 1`,
		`tempogate_build_info{commit="unknown",version="dev"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape is missing %q", want)
		}
	}

	app.RequireStop()
	if body := scrape(t, p.Handler); strings.Contains(body, "tempogate_") {
		t.Errorf("a stopped app still exports instruments:\n%s", body)
	}
}
