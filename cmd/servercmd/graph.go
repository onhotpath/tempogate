package servercmd

import (
	"context"
	"errors"
	"log/slog"

	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"
	"go.uber.org/zap"

	"github.com/onhotpath/tempogate/admin"
	"github.com/onhotpath/tempogate/api"
	"github.com/onhotpath/tempogate/config"
	"github.com/onhotpath/tempogate/keys"
	"github.com/onhotpath/tempogate/oidc"
	"github.com/onhotpath/tempogate/oidc/google"
	"github.com/onhotpath/tempogate/state/sqlite"
)

// deps hands a subcommand its dependencies only when it runs, and releases
// them (closing the state store) when run returns.
//
// The root graph must not depend on the server stack: fx constructs every
// provider an invoked function needs, so if the cobra tree depended on
// *api.Servers, `migrate`, `keys`, `version` and even `--help` would fail on
// a missing OIDC_SESSION_SIGNING_KEY that only `serve` uses.
type deps[P any] func(ctx context.Context, run func(P) error) error

// graph is the slice of the root graph that every server sub-graph shares:
// the loaded configuration and the process loggers.
type graph struct {
	base fx.Option
}

type graphParams struct {
	fx.In

	Config *config.Config
	Zap    *zap.Logger
	Slog   *slog.Logger
}

func newGraph(p graphParams) graph {
	return graph{base: fx.Options(
		config.Supply(p.Config),
		fx.Supply(p.Zap, p.Slog),
		fx.WithLogger(func() fxevent.Logger {
			return &fxevent.ZapLogger{Logger: p.Zap.WithOptions(zap.IncreaseLevel(zap.WarnLevel))}
		}),
	)}
}

// lazy returns deps that build P from g's base plus modules, on demand.
func lazy[P any](g graph, modules ...fx.Option) deps[P] {
	return func(ctx context.Context, run func(P) error) (err error) {
		var p P
		app := fx.New(g.base, fx.Options(modules...), fx.Invoke(func(in P) { p = in }))
		if err := app.Err(); err != nil {
			return err
		}
		if err := app.Start(ctx); err != nil {
			return err
		}
		defer func() { err = errors.Join(err, app.Stop(context.WithoutCancel(ctx))) }()
		return run(p)
	}
}

// storeModules is all `migrate` and `sessions` need.
func storeModules() []fx.Option {
	return []fx.Option{sqlite.Fx()}
}

// keysModules is all `keys` needs: the store plus the keypair aggregate.
func keysModules() []fx.Option {
	return []fx.Option{sqlite.Fx(), keys.Fx()}
}

// serverModules is the full HTTP server stack `serve` and `gen-oas` need.
// Building it validates the OIDC configuration, so only those two
// subcommands fail when it is missing.
func serverModules() []fx.Option {
	return []fx.Option{
		fx.Invoke(checkIssuer),
		sqlite.Fx(),
		keys.Fx(),
		oidc.Fx(),
		admin.Fx(),
		google.Fx(),
		api.Fx(),
	}
}

// checkIssuer refuses an insecure OIDC_ISSUER before the server stack is
// built, so the operator sees that error rather than whichever other setting
// happens to be missing too. Only the subcommands that build the issuer run
// it: migrate, keys and version never need OIDC configuration.
func checkIssuer(cfg *config.Config, logger *zap.Logger) error {
	if err := config.ValidateIssuer(cfg.OIDC.Issuer); err != nil {
		if !cfg.OIDC.AllowInsecureIssuer {
			return err
		}
		logger.Warn("insecure OIDC issuer allowed by OIDC_ALLOW_INSECURE_ISSUER; do not use in production",
			zap.String("issuer", cfg.OIDC.Issuer))
	}
	return nil
}
