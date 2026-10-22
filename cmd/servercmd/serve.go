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
	"context"
	"errors"
	"fmt"
	"net"
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

type serveParams struct {
	fx.In

	Logger        *zap.Logger
	Store         *sqlite.Store
	Reaper        *sqlite.Reaper
	Keys          *keys.Keys
	Servers       *api.Servers
	Readiness     *api.Readiness
	Listener      config.Listener     `name:"http"`
	AdminListener config.Listener     `name:"admin"`
	Server        config.ServerConfig `name:"http_server"`
	KeysReload    time.Duration       `name:"keys_reload_interval"`
	LogRequests   bool                `name:"log_requests"`

	DocsEnabled     bool `name:"api_docs_enabled"`
	IssuerPlainHTTP bool `name:"oidc_issuer_plain_http"`
}

// httpServers builds the public and admin servers. Two http.Server
// instances, two muxes: the public listener literally has no /admin/*
// handler, so admin reachability is a property of binding, not of
// middleware. Both share newHTTPServer so the admin listener is never
// softer than the public one, and both get the access log when
// LOG_REQUESTS is on.
func httpServers(p serveParams) (public, admin *http.Server) {
	publicMux := http.NewServeMux()
	publicMux.Handle("/", p.Servers.Public.Handler)

	adminMux := http.NewServeMux()
	adminMux.Handle("/", p.Servers.Admin.Handler)

	var publicHandler, adminHandler http.Handler = publicMux, adminMux
	if p.LogRequests {
		publicHandler = accessLog(p.Logger, "public", publicHandler)
		adminHandler = accessLog(p.Logger, "admin", adminHandler)
	}

	return newHTTPServer(p.Listener.String(), publicHandler, p.Server),
		newHTTPServer(p.AdminListener.String(), adminHandler, p.Server)
}

func newHTTPServer(addr string, handler http.Handler, cfg config.ServerConfig) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		MaxHeaderBytes:    cfg.MaxHeaderBytes,
	}
}

// errAPIDocsNeedDevIssuer refuses API docs anywhere but a local dev stack,
// whatever the deployment method: they map every public endpoint without
// authentication, and the docs page loosens its CSP to load from a CDN.
var errAPIDocsNeedDevIssuer = errors.New("API_DOCS_ENABLED is for local development only and requires a plain-http OIDC_ISSUER; " +
	"use `tempogate gen-oas` (and `tempogate gen-oas --admin`) to get the OpenAPI specs elsewhere")

func newServeCmd(load deps[serveParams]) *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Run the tempogate HTTP server",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return load(cmd.Context(), func(p serveParams) error { return serve(cmd.Context(), p) })
		},
	}
}

func serve(ctx context.Context, p serveParams) error {
	if p.DocsEnabled && !p.IssuerPlainHTTP {
		return errAPIDocsNeedDevIssuer
	}
	if err := storeReady(ctx, p.Store); err != nil {
		return err
	}

	// Load (or bootstrap) the signing keypair before either listener
	// binds so /.well-known/jwks.json serves the active key from the
	// first accepted request and the admin signer can mint integration
	// JWTs.
	if err := p.Keys.Init(ctx); err != nil {
		return fmt.Errorf("keys init: %w", err)
	}
	warnUnencryptedKeys(p.Logger, p.Keys)
	if p.KeysReload <= 0 {
		return fmt.Errorf("KEYS_RELOAD_INTERVAL must be positive, got %s", p.KeysReload)
	}

	// Both run under xrun.All so a failure on either tears down the
	// process.
	public, admin := httpServers(p)
	publicAddr, adminAddr := public.Addr, admin.Addr
	logger := p.Logger.Named("server")

	// Re-reading keypairs lets `tempogate keys generate|retire`, run from
	// another process against the same store, take effect without a
	// restart. The admin retire route reloads at once on its own.
	keyReloader := xrun.ComponentFunc(func(ctx context.Context) error {
		return p.Keys.Watch(ctx, p.KeysReload, func(err error) {
			logger.Warn("signing keys reload failed; keeping the loaded set", zap.Error(err))
		})
	})

	return xrun.All(
		xrun.NoTimeout,
		// Started only once the schema is known current, and
		// stopped with the listeners: a sweep in flight is
		// cancelled through ctx.
		xrun.ComponentFunc(p.Reaper.Run),
		keyReloader,
		httpServer(httpServerOptions{
			server:          public,
			shutdownTimeout: p.Server.ShutdownTimeout,
			onListening: func(net.Addr) {
				logger.Info("starting public http server", zap.String("addr", publicAddr))
				p.Readiness.Mark()
			},
			onStopping: func() {
				logger.Info("stopping public http server", zap.String("addr", publicAddr))
			},
		}),
		httpServer(httpServerOptions{
			server:          admin,
			shutdownTimeout: p.Server.ShutdownTimeout,
			onListening: func(net.Addr) {
				logger.Info("starting admin http server", zap.String("addr", adminAddr))
			},
			onStopping: func() {
				logger.Info("stopping admin http server", zap.String("addr", adminAddr))
			},
		}),
	).Run(ctx)
}

// warnUnencryptedKeys flags keys left in clear after a KEK was configured:
// they still work, but are exposed until `tempogate keys encrypt` runs.
func warnUnencryptedKeys(logger *zap.Logger, k *keys.Keys) {
	if kids := k.UnencryptedKids(); len(kids) > 0 {
		logger.Warn("signing keys are stored unencrypted although KEYS_ENCRYPTION_KEY is set; run `tempogate keys encrypt`",
			zap.Strings("kids", kids))
	}
}
