package servercmd

import (
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"
	"go.uber.org/zap"

	"github.com/onhotpath/tempogate/api"
	"github.com/onhotpath/tempogate/config"
	"github.com/onhotpath/tempogate/keys"
	"github.com/onhotpath/tempogate/state/sqlite"
)

// TestFxWiresServerSubcommands proves Fx() (via asCommand) contributes serve,
// migrate, keys and gen-oas into the "commands" value group the root
// dispatcher collects — the integration the full app assembly relies on, and
// the reason none of these subcommands appear in the lean build.
func TestFxWiresServerSubcommands(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	store, err := sqlite.New(sqlite.WithPath(path))
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	var cmds []*cobra.Command
	app := fxtest.New(t,
		fx.Provide(
			zap.NewNop,
			func() *sqlite.Store { return store },
			func() *keys.Keys { return keys.New(keys.WithStore(store)) },
			api.NewReadiness,
			func(r *api.Readiness) *api.Servers { return api.New(r) },
			fx.Annotate(
				func() config.Listener { return config.Listener{} },
				fx.ResultTags(`name:"http"`),
			),
			fx.Annotate(
				func() config.Listener { return config.Listener{} },
				fx.ResultTags(`name:"admin"`),
			),
			fx.Annotate(
				func() string { return path },
				fx.ResultTags(`name:"sqlite_path"`),
			),
		),
		Fx(),
		fx.Invoke(func(p struct {
			fx.In
			Commands []*cobra.Command `group:"commands"`
		}) {
			cmds = p.Commands
		}),
	)
	app.RequireStart().RequireStop()

	got := map[string]bool{}
	for _, c := range cmds {
		got[c.Name()] = true
	}
	for _, want := range []string{"serve", "migrate", "keys", "gen-oas"} {
		require.Truef(t, got[want], "Fx() must contribute %q into the commands group", want)
	}
}
