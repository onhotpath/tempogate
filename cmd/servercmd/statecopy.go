package servercmd

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"slices"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/fx"
	"go.uber.org/zap"

	"github.com/onhotpath/tempogate/state/postgres"
	"github.com/onhotpath/tempogate/state/sqlite"
)

// stateImporter is the Postgres store as `state copy` writes to it.
type stateImporter interface {
	Ping(ctx context.Context) error
	Migrate(ctx context.Context) error
	Import(ctx context.Context, src postgres.Source, opts ...postgres.ImportOption) (map[string]int64, error)
}

type stateCopyParams struct {
	fx.In

	Logger            *zap.Logger
	Target            stateImporter
	SqlitePath        string        `name:"sqlite_path"`
	SqliteBusyTimeout time.Duration `name:"sqlite_busy_timeout"`
}

// copyModules builds the Postgres store from STATE_POSTGRES_* whatever
// STATE_DRIVER says: the copy runs before the switch, often with the SQLite
// configuration still in place.
func copyModules() []fx.Option {
	return []fx.Option{
		postgres.Fx(),
		fx.Provide(func(s *postgres.Store) stateImporter { return s }),
	}
}

func newStateCmd(load deps[stateCopyParams]) *cobra.Command {
	root := &cobra.Command{
		Use:   "state",
		Short: "Move state between state store backends",
	}
	root.AddCommand(newStateCopyCmd(load))
	return root
}

func newStateCopyCmd(load deps[stateCopyParams]) *cobra.Command {
	var (
		from  string
		force bool
	)
	c := &cobra.Command{
		Use:   "copy",
		Short: "Copy the SQLite state store into the Postgres one",
		Long: "Copy every row of a SQLite state store (signing keys, integration keys and their revocations, " +
			"sessions, refresh tokens and pending sign-ins) into the Postgres database STATE_POSTGRES_DSN " +
			"(or STATE_POSTGRES_DSN_FILE) names, so a deployment can switch STATE_DRIVER to postgres " +
			"without rotating keys or signing anyone out. The source must be migrated by this release; " +
			"the target is migrated first. The copy is one transaction: it writes everything or nothing. " +
			"A target that already holds state is refused unless --force, which deletes that state in the " +
			"same transaction. Stop every tempogate replica first: writes made to the source after the copy are lost.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			return load(ctx, func(p stateCopyParams) error {
				if from == "" {
					from = p.SqlitePath
				}
				return copyState(ctx, cmd, p, from, force)
			})
		},
	}
	c.Flags().StringVar(&from, "from", "", "SQLite database to copy from (default STATE_SQLITE_PATH)")
	c.Flags().BoolVar(&force, "force", false, "replace the state the Postgres database already holds")
	return c
}

func copyState(ctx context.Context, cmd *cobra.Command, p stateCopyParams, from string, force bool) error {
	// Opening a missing path would create an empty database there, and copy
	// nothing.
	if _, err := os.Stat(from); errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("source %s does not exist; pass --from or set STATE_SQLITE_PATH", from)
	} else if err != nil {
		return fmt.Errorf("source: %w", err)
	}
	src, err := sqlite.New(sqlite.WithPath(from), sqlite.WithBusyTimeout(p.SqliteBusyTimeout),
		sqlite.WithLogger(p.Logger.Named("sqlite")))
	if err != nil {
		return err
	}
	defer func() { _ = src.Close() }()
	if err := storeReady(ctx, src); err != nil {
		return fmt.Errorf("source %s: %w (run `tempogate migrate` against it with STATE_DRIVER=sqlite first)", from, err)
	}

	if err := p.Target.Ping(ctx); err != nil {
		return fmt.Errorf("target unreachable: %w", err)
	}
	if err := p.Target.Migrate(ctx); err != nil {
		return fmt.Errorf("target: %w", err)
	}
	var opts []postgres.ImportOption
	if force {
		opts = append(opts, postgres.ImportForce())
	}
	copied, err := p.Target.Import(ctx, src, opts...)
	if errors.Is(err, postgres.ErrTargetNotEmpty) {
		return fmt.Errorf("%w; pass --force to replace it", err)
	}
	if err != nil {
		return err
	}

	for _, table := range slices.Sorted(maps.Keys(copied)) {
		cmd.Printf("%s: %d rows\n", table, copied[table])
	}
	cmd.Printf("copied %s into Postgres; set STATE_DRIVER=postgres to serve from it\n", from)
	return nil
}
