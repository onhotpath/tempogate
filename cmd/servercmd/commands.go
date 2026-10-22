package servercmd

import (
	"github.com/spf13/cobra"
	"go.uber.org/fx"
)

// asCommand annotates a *cobra.Command-returning constructor so its result is
// fed into the "commands" value group the root dispatcher (package cmd)
// collects. Duplicated from package cmd's helper on purpose: servercmd stays
// self-contained so it never has to import cmd.
func asCommand(constructor any) any {
	return fx.Annotate(constructor, fx.ResultTags(`group:"commands"`))
}

// Fx contributes the server-bound subcommands (serve, migrate, keys,
// sessions, gen-oas) into the cobra command group. Wired only by the full app
// assembly; absent from the lean CLI build.
//
// The commands themselves depend only on the shared graph base; each builds
// the server modules it needs when it runs (see deps).
func Fx() fx.Option {
	return fx.Options(
		fx.Provide(newGraph),
		fx.Provide(
			asCommand(func(g graph) *cobra.Command {
				return newServeCmd(lazy[serveParams](g, serverModules()...))
			}),
			asCommand(func(g graph) *cobra.Command {
				return newMigrateCmd(lazy[migrateParams](g, storeModules()...))
			}),
			asCommand(func(g graph) *cobra.Command {
				return newKeysCmd(lazy[keysParams](g, keysModules()...))
			}),
			asCommand(func(g graph) *cobra.Command {
				return newSessionsCmd(lazy[sessionsParams](g, storeModules()...))
			}),
			asCommand(func(g graph) *cobra.Command {
				return newGenOASCmd(lazy[genOASParams](g, serverModules()...))
			}),
		),
	)
}
