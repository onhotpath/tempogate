package servercmd

import (
	"github.com/spf13/cobra"
	"go.uber.org/fx"
	"go.uber.org/zap"

	"github.com/onhotpath/tempogate/state/sqlite"
)

type migrateParams struct {
	fx.In

	Logger     *zap.Logger
	Store      *sqlite.Store
	SqlitePath string `name:"sqlite_path"`
}

func newMigrateCmd(p migrateParams) *cobra.Command {
	return &cobra.Command{
		Use:   "migrate",
		Short: "Apply pending schema migrations to the state store",
		RunE: func(cmd *cobra.Command, _ []string) error {
			logger := p.Logger.Named("migrate")
			logger.Info("applying migrations", zap.String("path", p.SqlitePath))
			if err := p.Store.Migrate(cmd.Context()); err != nil {
				return err
			}
			logger.Info("migrations up to date")
			return nil
		},
	}
}
