package cmd

import (
	"context"
	"sort"

	"github.com/spf13/cobra"
	"go.uber.org/fx"
	"go.uber.org/zap"

	"github.com/onhotpath/tempogate/log"
)

// Fx wires the cobra root dispatcher. Subcommands are not referenced here:
// each is contributed into the "commands" value group by its own provider —
// the always-present CLI ones via CLICommandsFx, the server-bound ones
// (serve/migrate/keys) via cmd/servercmd, which the lean build never wires.
// This package therefore imports nothing server-specific, which is what lets
// the lean binary drop the SQLite/OIDC/API subtree.
func Fx() fx.Option { return fx.Invoke(Run) }

// rootParams is everything the dispatcher itself needs. Subcommand
// dependencies live in each subcommand's own provider, not here.
type rootParams struct {
	fx.In

	Lifecycle  fx.Lifecycle
	Shutdowner fx.Shutdowner
	Logger     *zap.Logger

	Commands []*cobra.Command `group:"commands"`
}

// rootCommand assembles the cobra tree from whatever subcommands the graph
// contributed. Split out of Run so the wiring is unit-testable without
// standing up the fx lifecycle. Commands are sorted by name for a stable
// `--help` ordering regardless of fx group resolution order.
func rootCommand(p rootParams) *cobra.Command {
	cmds := append([]*cobra.Command(nil), p.Commands...)
	sort.Slice(cmds, func(i, j int) bool { return cmds[i].Name() < cmds[j].Name() })
	return NewRootCmd(cmds...)
}

// Run is the cobra dispatcher fx invokes after the graph builds.
//
// On OnStart it spawns the cobra command in a goroutine; the dispatcher's
// ctx is cancelled on OnStop so long-running subcommands (serve) that block
// on ctx can unwind gracefully. One-shot subcommands (version, migrate)
// finish immediately and trigger Shutdowner themselves.
func Run(p rootParams) {
	ctx, cancel := context.WithCancel(context.Background())
	rootCmd := rootCommand(p)
	done := make(chan struct{})

	runCmd := func(ctx context.Context) {
		defer close(done)
		if err := rootCmd.ExecuteContext(ctx); err != nil {
			log.Failure(p.Logger, "command failed", err)
			_ = p.Shutdowner.Shutdown(fx.ExitCode(1))
			return
		}
		_ = p.Shutdowner.Shutdown()
	}

	p.Lifecycle.Append(fx.Hook{
		OnStart: func(_ context.Context) error {
			go runCmd(ctx)
			return nil
		},
		OnStop: func(_ context.Context) error {
			cancel()
			<-done
			return nil
		},
	})
}
