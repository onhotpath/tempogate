package servercmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"go.uber.org/fx"

	"github.com/onhotpath/tempogate/api"
)

type genOASParams struct {
	fx.In

	Servers *api.Servers
}

// newGenOASCmd emits the OpenAPI 3.1 document for one of the Huma APIs the
// server builds. The two surfaces (public, admin) are structurally separate,
// so their specs are too: the default --admin=false produces the OIDC + health
// public spec, and --admin produces the admin-only spec. Running both and
// diffing makes leakage between them surface as a spec change.
func newGenOASCmd(p genOASParams) *cobra.Command {
	var (
		admin  bool
		format string
	)
	c := &cobra.Command{
		Use:   "gen-oas",
		Short: "Emit OpenAPI 3.1 spec for the public (default) or admin (--admin) surface",
		RunE: func(cmd *cobra.Command, _ []string) error {
			surface := p.Servers.Public
			if admin {
				surface = p.Servers.Admin
			}
			oapi := surface.API.OpenAPI()

			var (
				b   []byte
				err error
			)
			switch strings.ToLower(format) {
			case "yaml", "yml":
				b, err = oapi.YAML()
			case "json":
				b, err = oapi.MarshalJSON()
			default:
				return fmt.Errorf("unknown format %q (want yaml or json)", format)
			}
			if err != nil {
				return fmt.Errorf("marshal openapi: %w", err)
			}
			if _, err := cmd.OutOrStdout().Write(b); err != nil {
				return err
			}
			return nil
		},
	}
	c.Flags().BoolVar(&admin, "admin", false, "emit the admin surface spec instead of the public one")
	c.Flags().StringVarP(&format, "format", "f", "yaml", "output format: yaml or json")
	return c
}
