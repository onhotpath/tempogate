package metrics

import (
	"net/http"

	"go.uber.org/fx"

	"github.com/onhotpath/tempogate/buildinfo"
	"github.com/onhotpath/tempogate/oidc"
	"github.com/onhotpath/tempogate/state/postgres"
	"github.com/onhotpath/tempogate/state/sqlite"
)

func newFx() *Metrics {
	return New(WithBuildInfo(buildinfo.Version(), buildinfo.Commit()))
}

func handler(m *Metrics) http.Handler { return m.Handler() }

// Fx provides *Metrics as every consumer-side observer interface it
// satisfies, plus the exposition handler the serve command mounts on the
// admin listener. The consumers declare those dependencies optional, so a
// graph without this module simply records nothing.
func Fx() fx.Option {
	return fx.Options(
		fx.Provide(
			fx.Annotate(
				newFx,
				fx.As(new(oidc.LoginObserver)),
				fx.As(new(oidc.TokenObserver)),
				fx.As(new(oidc.RateLimitObserver)),
				fx.As(new(oidc.AuthzObserver)),
				fx.As(new(oidc.UpstreamObserver)),
				fx.As(new(sqlite.ErrorObserver)),
				fx.As(new(postgres.ErrorObserver)),
				fx.As(fx.Self()),
			),
		),
		fx.Provide(
			fx.Annotate(
				handler,
				fx.ResultTags(`name:"metrics_handler"`),
			),
		),
	)
}
