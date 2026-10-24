package servercmd

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"
	"go.uber.org/zap"

	"github.com/onhotpath/tempogate/config"
)

// TestFxWiresServerSubcommands proves Fx() (via asCommand) contributes serve,
// migrate, keys, sessions, state and gen-oas into the "commands" value group the root
// dispatcher collects - the integration the full app assembly relies on, and
// the reason none of these subcommands appear in the lean build. The root
// graph supplies only configuration and loggers: Fx() must not need anything
// from the server stack to register its commands.
func TestFxWiresServerSubcommands(t *testing.T) {
	cmds := fxCommands(t)
	for _, want := range []string{"serve", "migrate", "keys", "sessions", "state", "gen-oas"} {
		require.NotNilf(t, cmds[want], "Fx() must contribute %q into the commands group", want)
	}
}

// fxCommands starts a root-like graph (config + loggers + Fx) and returns the
// contributed commands by name.
func fxCommands(t *testing.T) map[string]*cobra.Command {
	t.Helper()
	cmds := map[string]*cobra.Command{}
	app := fxtest.New(t,
		config.Fx(),
		fx.Provide(zap.NewNop, slog.Default),
		Fx(),
		fx.Invoke(func(p struct {
			fx.In
			Commands []*cobra.Command `group:"commands"`
		}) {
			for _, c := range p.Commands {
				cmds[c.Name()] = c
			}
		}),
	)
	app.RequireStart()
	t.Cleanup(app.RequireStop)
	return cmds
}

// TestFxBuildsCommandDepsOnlyWhenRun is the regression guard for the lazy
// server graph: with only STATE_SQLITE_PATH configured, Fx() must still
// contribute every server subcommand (so `--help` works), `migrate`, `keys`
// and `sessions` must run, and only `serve` and `gen-oas` (which build the
// API) may fail, naming the missing OIDC setting.
func TestFxBuildsCommandDepsOnlyWhenRun(t *testing.T) {
	t.Setenv("STATE_SQLITE_PATH", filepath.Join(t.TempDir(), "state.db"))
	t.Setenv("OIDC_SESSION_SIGNING_KEY", "")
	t.Setenv("OIDC_CLIENTS", "")

	cmds := fxCommands(t)

	exec := func(name string, args ...string) error {
		c := cmds[name]
		require.NotNilf(t, c, "Fx() must contribute %q", name)
		c.SetArgs(args)
		c.SetOut(new(testWriter))
		c.SetErr(new(testWriter))
		return c.ExecuteContext(context.Background())
	}

	require.NoError(t, exec("migrate"))
	require.NoError(t, exec("keys", "generate"))
	require.NoError(t, exec("sessions", "list"))

	for _, name := range []string{"serve", "gen-oas"} {
		err := exec(name)
		require.Errorf(t, err, "%s needs the full server stack", name)
		require.Contains(t, err.Error(), "OIDC_SESSION_SIGNING_KEY is required")
	}
}
