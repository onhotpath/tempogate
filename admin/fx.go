package admin

import (
	"github.com/danielgtaylor/huma/v2"
	"go.uber.org/fx"

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
	DenylistCache *keys.DenylistCache
}

// newKeysRegistrar builds the /admin/keys handler over the KeyRegistry
// provided by state/sqlite's adapter and the Signer provided by keys.Fx, then
// returns its Register method as a Huma registrar. The result is fanned into
// the api package's "admin_registrars" group, which the api builder mounts on
// the admin Surface only — a separate mux + Huma API the serve command binds
// to its own private listener.
func newKeysRegistrar(p keysParams) func(huma.API) {
	h := NewKeys(p.Registry, p.Signer, WithDenylistHydrator(p.DenylistCache))
	return h.Register
}

// Fx contributes the /admin/keys registrar into api's "admin_registrars"
// group: the routes live on the admin Surface, never on the public one.
// KeyRegistry is satisfied by state/sqlite's adapter constructor (see
// state/sqlite/admin_adapter.go); the Signer is provided by keys.Fx.
func Fx() fx.Option {
	return fx.Options(
		fx.Provide(
			fx.Annotate(
				newKeysRegistrar,
				fx.ResultTags(`group:"admin_registrars"`),
			),
		),
	)
}
