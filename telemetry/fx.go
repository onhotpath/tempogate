package telemetry

import (
	"net/http"

	"go.uber.org/fx"

	"github.com/onhotpath/tempogate/buildinfo"
	"github.com/onhotpath/tempogate/observe"
)

func newProviderFx(lc fx.Lifecycle) (*Provider, error) {
	p, err := NewProvider(WithBuildInfo(buildinfo.Version(), buildinfo.Commit()))
	if err != nil {
		return nil, err
	}
	lc.Append(fx.StopHook(p.Shutdown))
	return p, nil
}

func newMeter(p *Provider) observe.Meter { return p.Meter() }

func handler(p *Provider) http.Handler { return p.Handler() }

// Fx provides the observe.Meter every feature package declares its metrics
// through, and the exposition handler the serve command mounts on the admin
// listener. The consumers take the Meter as optional, so a graph without
// this module records nothing.
func Fx() fx.Option {
	return fx.Options(
		fx.Provide(newProviderFx, newMeter),
		fx.Provide(
			fx.Annotate(
				handler,
				fx.ResultTags(`name:"metrics_handler"`),
			),
		),
	)
}
