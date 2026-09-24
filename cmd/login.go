package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/onhotpath/tempogate/cli"
)

// issuerEnvVar is the client-side issuer override. It is deliberately distinct
// from the server's OIDC__ISSUER: `tempogate login` runs on a developer laptop
// and points at a *remote* tempogate, so it carries its own env var rather
// than reusing server configuration that is irrelevant on a client.
const issuerEnvVar = "TEMPOGATE__ISSUER"

// loginModeEnvVar is the no-flag escape hatch for selecting the device flow,
// used by CI / wrapper scripts that cannot easily pass `--device` through.
// Only the literal value "device" flips the dispatch; anything else is
// treated as the default loopback mode. An explicit `--device` (or
// `--device=false`) on the command line always wins over this env.
const loginModeEnvVar = "TEMPOGATE_LOGIN_MODE"

// loginRunner builds the loopback Flow and runs it. It is a package var purely
// so tests can drive the command against a mock issuer without launching a
// real system browser; production code never reassigns it.
var loginRunner = func(ctx context.Context, opts ...cli.Option) (cli.Token, error) {
	return cli.New(opts...).Run(ctx)
}

// deviceRunner builds the RFC 8628 DeviceFlow and runs it. Same seam shape as
// loginRunner so tests can inject a deterministic Token without making any
// HTTP round-trip; production code never reassigns it.
var deviceRunner = func(ctx context.Context, opts ...cli.DeviceOption) (cli.Token, error) {
	return cli.NewDeviceFlow(opts...).Run(ctx)
}

// resolveTokenPath honours an explicit --token-file and otherwise falls back
// to ~/.tempogate/token.json. It is shared by `login` (writer) and `token`
// (reader) so the two never disagree about where the credential lives.
func resolveTokenPath(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	return cli.DefaultTokenPath()
}

func newLoginCmd(logger *zap.Logger) *cobra.Command {
	var issuer, clientID, tokenFile string
	var port int
	var device bool
	var devicePollDeadline time.Duration

	c := &cobra.Command{
		Use:   "login",
		Short: "Sign in via browser, persist the token, and print it",
		Long: "Two acquisition modes share the same persisted Token and refresh path;\n" +
			"only the initial sign-in step differs:\n" +
			"\n" +
			"  default (loopback)  Starts a one-shot 127.0.0.1 HTTP server and opens\n" +
			"                      the system browser to the tempogate issuer\n" +
			"                      (RFC 8252). Use on a workstation with a browser.\n" +
			"\n" +
			"  --device            Runs the OAuth2 device authorization grant\n" +
			"                      (RFC 8628): tempogate prints a short user_code\n" +
			"                      + verification URL on stderr; you complete sign-in\n" +
			"                      on any device with a browser. Use --device when\n" +
			"                      this host has no browser (remote shell, cloud-code\n" +
			"                      VM, container). Equivalent env: " + loginModeEnvVar + "=device.\n" +
			"\n" +
			"Either way, the token is persisted to ~/.tempogate/token.json (mode 0600)\n" +
			"and the access token is printed to stdout, so\n" +
			"  export TEMPORAL_AUTH_TOKEN=$(tempogate login [--device])\n" +
			"captures just the token. Afterwards, `tempogate token` reuses the\n" +
			"persisted token and refreshes it transparently near expiry.",
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

			// Flag beats env: only consult TEMPOGATE_LOGIN_MODE when --device
			// was not explicitly set, so `--device=false` reliably forces the
			// loopback path even with the env var pointing at "device".
			useDevice := device
			if !cmd.Flags().Changed("device") && os.Getenv(loginModeEnvVar) == "device" {
				useDevice = true
			}

			log := logger.Named("login")

			var tok cli.Token
			if useDevice {
				if devicePollDeadline < 0 {
					return fmt.Errorf("--device-poll-deadline must be non-negative, got %s", devicePollDeadline)
				}
				log.Info("starting device-flow login", zap.String("issuer", issuer))
				opts := []cli.DeviceOption{
					cli.WithDeviceIssuer(issuer),
					cli.WithDeviceClientID(clientID),
					cli.WithDeviceOutput(cmd.ErrOrStderr()),
				}
				if devicePollDeadline > 0 {
					opts = append(opts, cli.WithDevicePollDeadline(devicePollDeadline))
				}
				tok, err = deviceRunner(cmd.Context(), opts...)
			} else {
				log.Info("starting loopback login", zap.String("issuer", issuer))
				tok, err = loginRunner(cmd.Context(),
					cli.WithIssuer(issuer),
					cli.WithPort(port),
					cli.WithClientID(clientID),
					cli.WithOutput(cmd.ErrOrStderr()),
				)
			}
			if err != nil {
				return err
			}

			if err := cli.Save(path, tok); err != nil {
				return err
			}

			_, _ = fmt.Fprintf(cmd.ErrOrStderr(),
				"Signed in. Token saved to %s, valid until %s.\n",
				path, tok.ExpiresAt.Format(time.RFC3339))
			cmd.Println(tok.AccessToken)
			return nil
		},
	}

	c.Flags().StringVar(&issuer, "issuer", "", fmt.Sprintf("tempogate base URL (default $%s)", issuerEnvVar))
	c.Flags().IntVar(&port, "port", 0, "loopback port (0 = a free ephemeral port, recommended); ignored with --device")
	c.Flags().StringVar(&clientID, "client-id", "", "OAuth2 client_id registered with tempogate (default \"tempogate-cli\", or \"tempogate-device\" with --device)")
	c.Flags().StringVar(&tokenFile, "token-file", "", "where to persist the token (default ~/.tempogate/token.json)")
	c.Flags().BoolVar(&device, "device", false,
		"use the OAuth2 device authorization grant (RFC 8628) instead of the "+
			"loopback browser flow. Required when this host has no browser "+
			"(remote shell, cloud-code VM). Env: "+loginModeEnvVar+"=device.")
	c.Flags().DurationVar(&devicePollDeadline, "device-poll-deadline", 0,
		"cap how long --device polls before giving up. Defaults to the "+
			"issuer's advertised expires_in (typically 15m). Pass a shorter "+
			"value in CI to fail fast when the user does not approve; ignored "+
			"without --device.")
	return c
}
