// Package servercmd holds the server-bound subcommands (serve, migrate,
// keys) — the ones that need the SQLite state store and the OIDC/API stack.
//
// It is wired into the cobra command group only by the full app assembly
// (app/modules_full.go). The lean CLI build never imports this package, so
// the Go linker drops the entire server subtree (SQLite/libc/OIDC/API) from
// that binary. Build tags live exclusively in package app — leanness here is
// a property of not being imported, not of a //go:build constraint.
package servercmd

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gojekfarm/xrun"
	"github.com/spf13/cobra"
	"go.uber.org/fx"
	"go.uber.org/zap"

	"github.com/onhotpath/tempogate/api"
	"github.com/onhotpath/tempogate/config"
	"github.com/onhotpath/tempogate/keys"
	"github.com/onhotpath/tempogate/state/sqlite"
)

const readHeaderTimeout = 10 * time.Second

type serveParams struct {
	fx.In

	Logger        *zap.Logger
	Store         *sqlite.Store
	Keys          *keys.Keys
	Servers       *api.Servers
	Readiness     *api.Readiness
	Listener      config.Listener `name:"http"`
	AdminListener config.Listener `name:"admin"`
}

func newServeCmd(p serveParams) *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Run the tempogate HTTP server",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()

			if err := p.Store.Ping(ctx); err != nil {
				return fmt.Errorf("state store unreachable: %w", err)
			}
			if err := p.Store.IsCurrent(ctx); err != nil {
				return err
			}

			// Load (or bootstrap) the signing keypair before either listener
			// binds so /.well-known/jwks.json serves the active key from the
			// first accepted request and the admin signer can mint integration
			// JWTs.
			if err := p.Keys.Init(ctx); err != nil {
				return fmt.Errorf("keys init: %w", err)
			}

			// Two http.Server instances, two muxes — the public listener
			// literally has no /admin/* handler, so admin reachability is a
			// property of binding, not of middleware. Both run under
			// xrun.All so a failure on either tears down the process.
			publicAddr := p.Listener.String()
			adminAddr := p.AdminListener.String()
			logger := p.Logger.Named("server")

			publicMux := http.NewServeMux()
			publicMux.Handle("/", p.Servers.Public.Handler)

			adminMux := http.NewServeMux()
			adminMux.Handle("/", p.Servers.Admin.Handler)

			return xrun.All(
				xrun.NoTimeout,
				httpServer(httpServerOptions{
					server: &http.Server{
						Addr:              publicAddr,
						Handler:           publicMux,
						ReadHeaderTimeout: readHeaderTimeout,
					},
					onListening: func() {
						logger.Info("starting public http server", zap.String("addr", publicAddr))
						p.Readiness.Mark()
					},
					onStopping: func() {
						logger.Info("stopping public http server", zap.String("addr", publicAddr))
					},
				}),
				httpServer(httpServerOptions{
					server: &http.Server{
						Addr:              adminAddr,
						Handler:           adminMux,
						ReadHeaderTimeout: readHeaderTimeout,
					},
					onListening: func() {
						logger.Info("starting admin http server", zap.String("addr", adminAddr))
					},
					onStopping: func() {
						logger.Info("stopping admin http server", zap.String("addr", adminAddr))
					},
				}),
			).Run(ctx)
		},
	}
}
