package admin

import (
	"github.com/danielgtaylor/huma/v2"
	"go.uber.org/fx"
	"go.uber.org/zap"

	"github.com/onhotpath/tempogate/keys"
)

type keysParams struct {
	fx.In

	Registry KeyRegistry
	Signer   *keys.Signer
	// DenylistCache is the verifier-side cache the DELETE handler nudges
	// after a successful revoke so the in-process Verifier rejects the
	// freshly-revoked token without waiting for its TTL to expire. Injected
	// by exact type from keys.Fx; *keys.DenylistCache satisfies the
	// admin.DenylistHydrator interface structurally.
	DenylistCache     *keys.DenylistCache
	Logger            *zap.Logger
	AllowSystemGrants bool `name:"admin_allow_system_grants"`
}

// newKeysRegistrar builds the /admin/keys handler over the KeyRegistry
// provided by state/sqlite's adapter and the Signer provided by keys.Fx, then
// returns its Register method as a Huma registrar. The result is fanned into
// the api package's "admin_registrars" group, which the api builder mounts on
// the admin Surface only — a separate mux + Huma API the serve command binds
// to its own private listener.
func newKeysRegistrar(p keysParams) func(huma.API) {
	h := NewKeys(p.Registry, p.Signer,
		WithDenylistHydrator(p.DenylistCache),
		WithLogger(p.Logger.Named("admin")),
		WithSystemGrants(p.AllowSystemGrants),
	)
	return h.Register
}

type guardParams struct {
	fx.In

	Logger       *zap.Logger
	TokenSHA256  string   `name:"admin_token_sha256"`
	AllowedHosts []string `name:"admin_allowed_hosts"`
}

// newGuardInstaller validates the admin auth config and returns the Guard's
// Install as an admin middleware. A malformed digest fails graph
// construction, so `serve` refuses to start rather than run unauthenticated.
func newGuardInstaller(p guardParams) (func(huma.API), error) {
	digests, err := ParseTokenDigests(p.TokenSHA256)
	if err != nil {
		return nil, err
	}
	logger := p.Logger.Named("admin")
	if len(digests) == 0 {
		logger.Warn("admin API is locked: ADMIN_TOKEN_SHA256 is empty, so every /admin/* route except /admin/healthz answers 401")
	}
	g := NewGuard(
		WithTokenDigests(digests),
		WithAllowedHosts(p.AllowedHosts),
		WithGuardLogger(logger),
	)
	return g.Install, nil
}

// Fx contributes the /admin/keys registrar into api's "admin_registrars"
// group and the Guard into "admin_middlewares": the routes live on the admin
// Surface, never on the public one, and always behind the guard.
// KeyRegistry is satisfied by state/sqlite's adapter constructor (see
// state/sqlite/admin_adapter.go); the Signer is provided by keys.Fx.
func Fx() fx.Option {
	return fx.Options(
		fx.Provide(
			fx.Annotate(
				newKeysRegistrar,
				fx.ResultTags(`group:"admin_registrars"`),
			),
			fx.Annotate(
				newGuardInstaller,
				fx.ResultTags(`group:"admin_middlewares"`),
			),
		),
	)
}
