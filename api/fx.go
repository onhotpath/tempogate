package api

import (
	"github.com/danielgtaylor/huma/v2"
	"go.uber.org/fx"
	"go.uber.org/zap"

	"github.com/onhotpath/tempogate/keys"
)

type serversParams struct {
	fx.In

	Readiness    *Readiness
	Keys         JWKSSource
	OIDCIssuer   string `name:"oidc_issuer"`
	OIDCBasePath string `name:"oidc_base_path"`
	DocsEnabled  bool   `name:"api_docs_enabled"`
	// Logger receives 5xx details; optional so api.Fx() builds in graphs
	// without logging (package tests). The app always provides one.
	Logger *zap.Logger `optional:"true"`

	// Registrars are contributed by feature packages (e.g. oidc) into the
	// shared group so they can append Huma operations without api importing
	// them. They land on the public Huma API; the OIDC surface moves under
	// basePath when one is configured.
	Registrars []func(huma.API) `group:"api_registrars"`

	// AdminRegistrars land on the admin Surface — a separate mux + Huma API
	// the serve command binds to its own private listener. admin/ contributes
	// the /admin/keys handler this way so there is no path from the public
	// surface to admin handlers.
	AdminRegistrars []func(huma.API) `group:"admin_registrars"`

	// Middlewares wrap the public OIDC operations (oidc contributes its
	// per-client rate limiter this way).
	Middlewares []func(huma.Context, func(huma.Context)) `group:"api_middlewares"`

	// AdminMiddlewares install middleware (the admin auth guard) on the
	// admin Surface ahead of every admin registrar.
	AdminMiddlewares []func(huma.API) `group:"admin_middlewares"`
}

func newServers(p serversParams) *Servers {
	opts := []Option{
		WithBasePath(p.OIDCBasePath),
		WithDocs(p.DocsEnabled),
		WithWellKnown(p.Keys, p.OIDCIssuer),
	}
	if p.Logger != nil {
		opts = append(opts, WithLogger(p.Logger.Named("http")))
	}
	for _, r := range p.Registrars {
		opts = append(opts, WithRegistrar(r))
	}
	for _, r := range p.AdminRegistrars {
		opts = append(opts, WithAdminRegistrar(r))
	}
	for _, m := range p.Middlewares {
		opts = append(opts, WithMiddleware(m))
	}
	for _, m := range p.AdminMiddlewares {
		opts = append(opts, WithAdminMiddleware(m))
	}
	return New(p.Readiness, opts...)
}

// keysAsJWKSSource adapts the concrete *keys.Keys (provided by keys.Fx) to
// api's narrow JWKSSource. The binding lives here, in the consumer, rather
// than via fx.As in keys.Fx: keys is the lower-level domain package and must
// not import api. *keys.Keys satisfies JWKSSource structurally; this is just
// the typed hand-off.
func keysAsJWKSSource(k *keys.Keys) JWKSSource { return k }

func Fx() fx.Option {
	return fx.Options(
		fx.Provide(NewReadiness),
		fx.Provide(keysAsJWKSSource),
		fx.Provide(newServers),
	)
}
