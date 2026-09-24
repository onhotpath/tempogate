// Package app is the fx composition root for the tempogate binary.
//
// Subsequent modules (HTTP server, keys, …) plug their fx.Options into
// New via the functional-options pattern below.
package app

import (
	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"
	"go.uber.org/zap"

	"github.com/onhotpath/tempogate/cmd"
	"github.com/onhotpath/tempogate/config"
	"github.com/onhotpath/tempogate/log"
)

type appConfig struct {
	extra []fx.Option
}

type Option func(*appConfig)

// With appends an fx.Option to the composition root. Used by future modules
// (and by tests) to extend the graph without forking New.
func With(opts ...fx.Option) Option {
	return func(cfg *appConfig) { cfg.extra = append(cfg.extra, opts...) }
}

func New(opts ...Option) fx.Option {
	cfg := &appConfig{}
	for _, o := range opts {
		o(cfg)
	}
	base := []fx.Option{
		config.Fx(),
		log.Fx(),
		fx.WithLogger(func(l *zap.Logger) fxevent.Logger {
			return &fxevent.ZapLogger{Logger: l.WithOptions(zap.IncreaseLevel(zap.WarnLevel))}
		}),
		cmd.Fx(),
		cmd.CLICommandsFx(),
	}
	// serverModules is the build-tag seam: the full build (modules_full.go)
	// returns the SQLite/OIDC/API stack plus the serve/migrate/keys
	// subcommands; the lean CLI build (modules_lean.go) returns nil. These two
	// files are the ONLY place a //go:build constraint appears in tempogate.
	base = append(base, serverModules()...)
	return fx.Options(append(base, cfg.extra...)...)
}
