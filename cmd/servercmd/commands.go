package servercmd

import "go.uber.org/fx"

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
func Fx() fx.Option {
	return fx.Provide(
		asCommand(newServeCmd),
		asCommand(newMigrateCmd),
		asCommand(newKeysCmd),
		asCommand(newSessionsCmd),
		asCommand(newGenOASCmd),
	)
}
