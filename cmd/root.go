package cmd

import (
	"github.com/spf13/cobra"

	"github.com/onhotpath/tempogate/buildinfo"
)

// NewRootCmd assembles the tempogate cobra tree from the given subcommands.
// Which subcommands exist is decided by the fx graph (see CLICommandsFx and
// the build-tagged module assembly in package app), not hardcoded here, so a
// lean build that omits the server modules simply has fewer subcommands —
// no //go:build constraint leaks into this package.
func NewRootCmd(subcommands ...*cobra.Command) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:           "tempogate",
		Short:         "OIDC + OAuth2 authorization server for self-hosted Temporal",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       buildinfo.Version(),
	}
	rootCmd.SetVersionTemplate("{{.Version}}\n")
	for _, sc := range subcommands {
		rootCmd.AddCommand(sc)
	}
	return rootCmd
}
