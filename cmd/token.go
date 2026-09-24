package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/onhotpath/tempogate/cli"
)

// tokenRefresher resolves a usable token, renewing it near expiry. It is a
// package var so tests can stub the refresh without a real issuer; production
// code never reassigns it.
var tokenRefresher = func(ctx context.Context, path, issuer string) (cli.Token, error) {
	return cli.EnsureFresh(ctx, path, issuer)
}

func newTokenCmd(logger *zap.Logger) *cobra.Command {
	var issuer, tokenFile string

	c := &cobra.Command{
		Use:   "token",
		Short: "Print the persisted access token, refreshing it near expiry",
		Long: "Reads ~/.tempogate/token.json (written by `tempogate login`) and\n" +
			"prints the access token to stdout. If it expires within five minutes\n" +
			"it is transparently refreshed and the file rewritten. Designed for\n" +
			"shell substitution: export TEMPORAL_AUTH_TOKEN=$(tempogate token).",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if issuer == "" {
				issuer = os.Getenv(issuerEnvVar)
			}
			if issuer == "" {
				return fmt.Errorf("issuer is required: pass --issuer or set %s", issuerEnvVar)
			}

			path, err := resolveTokenPath(tokenFile)
			if err != nil {
				return err
			}

			// Debug, not Info: `tempogate token` is meant for shell
			// substitution, so it stays quiet at the default log level.
			logger.Named("token").Debug("resolving token",
				zap.String("issuer", issuer), zap.String("path", path))

			tok, err := tokenRefresher(cmd.Context(), path, issuer)
			if err != nil {
				return err
			}

			cmd.Println(tok.AccessToken)
			return nil
		},
	}

	c.Flags().StringVar(&issuer, "issuer", "", fmt.Sprintf("tempogate base URL (default $%s)", issuerEnvVar))
	c.Flags().StringVar(&tokenFile, "token-file", "", "token file to read/refresh (default ~/.tempogate/token.json)")
	return c
}
