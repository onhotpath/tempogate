package servercmd

import (
	"context"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"
	"go.uber.org/zap"

	"github.com/onhotpath/tempogate/admin"
	"github.com/onhotpath/tempogate/config"
	"github.com/onhotpath/tempogate/keys"
	"github.com/onhotpath/tempogate/state/postgres"
	"github.com/onhotpath/tempogate/state/sqlite"
)

// TestStateModuleBindsTheSelectedBackend: the subcommands reach the store
// only through stateStore, stateReaper and the consumer interfaces, all of
// which STATE_DRIVER's backend provides.
func TestStateModuleBindsTheSelectedBackend(t *testing.T) {
	cases := map[string]struct {
		state    config.StateConfig
		store    any
		reaper   any
		bootLock bool
	}{
		config.StateDriverSQLite: {
			state:  config.StateConfig{Driver: config.StateDriverSQLite, Sqlite: config.SqliteConfig{Path: t.TempDir() + "/state.db", MaxConns: 1}},
			store:  &sqlite.Store{},
			reaper: &sqlite.Reaper{},
		},
		config.StateDriverPostgres: {
			state: config.StateConfig{Driver: config.StateDriverPostgres, Postgres: config.PostgresConfig{
				DSN: "postgres://tempogate@127.0.0.1:1/tempogate", MaxConns: 2,
			}},
			store:    &postgres.Store{},
			reaper:   &postgres.Reaper{},
			bootLock: true,
		},
	}
	for driver, tc := range cases {
		t.Run(driver, func(t *testing.T) {
			var (
				store    stateStore
				reaper   stateReaper
				sessions admin.SessionStore
				feed     keys.ChangeFeed
				locker   keys.BootstrapLocker
			)
			app := fxtest.New(t,
				config.Supply(&config.Config{State: tc.state}),
				fx.Supply(zap.NewNop()),
				stateModule(driver),
				fx.Invoke(func(p struct {
					fx.In
					Store    stateStore
					Reaper   stateReaper
					Sessions admin.SessionStore
					Feed     keys.ChangeFeed
					Locker   keys.BootstrapLocker `optional:"true"`
				}) {
					store, reaper, sessions, feed, locker = p.Store, p.Reaper, p.Sessions, p.Feed, p.Locker
				}),
			)
			app.RequireStart()
			t.Cleanup(app.RequireStop)

			require.IsType(t, tc.store, store)
			require.IsType(t, tc.reaper, reaper)
			require.NotNil(t, sessions)
			require.Equal(t, store, feed, "one store backs every interface")
			require.Equal(t, tc.bootLock, locker != nil, "only a shared store serialises first-boot key generation")
		})
	}
}

func TestStateDriverIsCheckedWhenAStoreIsBuilt(t *testing.T) {
	t.Run("unknown", func(t *testing.T) {
		t.Setenv("STATE_DRIVER", "mysql")
		cmds := fxCommands(t)
		require.NotNil(t, cmds["migrate"], "an unknown driver does not stop the commands registering")
		require.ErrorContains(t, runCmd(cmds["migrate"]), `STATE_DRIVER must be "sqlite" or "postgres", got "mysql"`)
	})

	t.Run("postgres without verify-full", func(t *testing.T) {
		t.Setenv("STATE_DRIVER", "postgres")
		t.Setenv("STATE_POSTGRES_DSN", "postgres://tempogate:secret@db.example.com/tempogate")
		err := runCmd(fxCommands(t)["migrate"])
		require.ErrorContains(t, err, `STATE_POSTGRES_DSN host "db.example.com" must use sslmode=verify-full`)
		require.NotContains(t, err.Error(), "secret")
	})

	t.Run("postgres unreachable", func(t *testing.T) {
		t.Setenv("STATE_DRIVER", "postgres")
		t.Setenv("STATE_POSTGRES_DSN", "postgres://tempogate@127.0.0.1:1/tempogate?connect_timeout=2")
		require.ErrorContains(t, runCmd(fxCommands(t)["sessions"], "list"), "state store unreachable: postgres: ping: ")
	})
}

func runCmd(c *cobra.Command, args ...string) error {
	c.SetArgs(args)
	c.SetOut(new(testWriter))
	c.SetErr(new(testWriter))
	return c.ExecuteContext(context.Background())
}
