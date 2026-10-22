package servercmd

import (
	"github.com/spf13/cobra"
	"go.uber.org/fx"
	"go.uber.org/zap"

	"github.com/onhotpath/tempogate/config"
)

type migrateParams struct {
	fx.In

	Logger     *zap.Logger
	Store      stateStore
	Driver     string `name:"state_driver"`
	SqlitePath string `name:"sqlite_path"`
}

func newMigrateCmd(load deps[migrateParams]) *cobra.Command {
	return &cobra.Command{
		Use:   "migrate",
		Short: "Apply pending schema migrations to the state store",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return load(cmd.Context(), func(p migrateParams) error {
				logger := p.Logger.Named("migrate")
				fields := []zap.Field{zap.String("driver", p.Driver)}
				if p.Driver == config.StateDriverSQLite {
					fields = append(fields, zap.String("path", p.SqlitePath))
				}
				logger.Info("applying migrations", fields...)
				if err := p.Store.Migrate(cmd.Context()); err != nil {
					return err
				}
				logger.Info("migrations up to date")
				return nil
			})
		},
	}
}
