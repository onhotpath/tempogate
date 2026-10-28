// Package app is the fx composition root for the tempogate binary.
//
// Subsequent modules (HTTP server, keys, …) plug their fx.Options into
// New via the functional-options pattern below.
package app

import (
	"os"
	"time"

	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"

	"github.com/onhotpath/tempogate/cmd"
	"github.com/onhotpath/tempogate/config"
	"github.com/onhotpath/tempogate/log"
)

// stopTimeout is fx's hard ceiling on stopping the app.
const stopTimeout = time.Minute

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
	boot := log.NewBootLogger(os.Stderr, "tempogate")
	base := []fx.Option{
		fx.Supply(config.ProcessPath()),
		// The HTTP servers bound their own drain with SERVER_SHUTDOWN_TIMEOUT
		// (default 15s). fx's 15s default would race that grace and abort the
		// remaining stop hooks (e.g. closing SQLite), so this is only a
		// backstop above any sane grace.
		fx.StopTimeout(stopTimeout),
		config.Fx(),
		log.Fx(),
		// The fx logger must not depend on the graph: see log.BootLogger.
		fx.WithLogger(func() fxevent.Logger { return boot }),
		fx.Invoke(boot.Use),
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
