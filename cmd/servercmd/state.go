package servercmd

import (
	"context"
	"fmt"

	"go.uber.org/fx"

	"github.com/onhotpath/tempogate/config"
	"github.com/onhotpath/tempogate/keys"
	"github.com/onhotpath/tempogate/state/postgres"
	"github.com/onhotpath/tempogate/state/sqlite"
)

// stateStore is what the server subcommands call on the state store itself,
// beyond the consumer interfaces the backend binds (state/doc.go): checking
// it is reachable and migrated, migrating it, and rewriting keys for
// `keys encrypt`. Every backend's *Store satisfies it.
type stateStore interface {
	Ping(ctx context.Context) error
	IsCurrent(ctx context.Context) error
	Migrate(ctx context.Context) error
	keys.PrivateKeyRewriter
}

// stateReaper deletes expired state until ctx is done; `serve` runs it.
type stateReaper interface {
	Run(ctx context.Context) error
}

// stateModule is the backend STATE_DRIVER selects. An unknown driver fails
// only the subcommands that build a store, so `version` and `--help` keep
// working.
func stateModule(driver string) fx.Option {
	switch driver {
	case config.StateDriverSQLite:
		return fx.Options(sqlite.Fx(), fx.Provide(
			func(s *sqlite.Store) stateStore { return s },
			func(r *sqlite.Reaper) stateReaper { return r },
		))
	case config.StateDriverPostgres:
		return fx.Options(postgres.Fx(), fx.Provide(
			func(s *postgres.Store) stateStore { return s },
			func(r *postgres.Reaper) stateReaper { return r },
		))
	default:
		return fx.Error(fmt.Errorf("STATE_DRIVER must be %q or %q, got %q",
			config.StateDriverSQLite, config.StateDriverPostgres, driver))
	}
}
