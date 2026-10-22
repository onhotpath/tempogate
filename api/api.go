// Package api is tempogate's HTTP surface. It produces two structurally
// isolated handler trees:
//
//   - Public: /healthz, /readyz, and the OIDC + .well-known endpoints
//     contributed by feature packages (oidc). The OIDC surface may move under
//     a base path when one is set (OIDC_ISSUER's path component); health
//     probes stay at the root regardless.
//   - Admin: /admin/healthz plus the /admin/* endpoints contributed by the
//     admin package. Lives on its own mux + Huma API so it can be bound to a
//     separate http.Server listener; the public mux has no admin handlers at
//     all and routes /admin/* to 404 as a property of having no entry, not as
//     a middleware decision.
//
// Separation is structural: the two Surfaces never share a mux or a Huma API,
// so generated OpenAPI specs split cleanly and no public-listener middleware
// can be bypassed to reach an admin handler.
package api

import (
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"

	"github.com/onhotpath/tempogate/buildinfo"
)

type apiConfig struct {
	// registrars land on the public Huma API. The OIDC surface (jwks +
	// discovery + token/authorize/userinfo) moves under basePath when one
	// is set so the discovery doc and the live routes stay in lockstep.
	registrars []func(huma.API)
	// adminRegistrars land on the admin Huma API, which is mounted on a
	// separate http.Handler from the public surface and meant for binding
	// to a private listener.
	adminRegistrars []func(huma.API)
	basePath        string
	docs            bool
}

type Option func(*apiConfig)

// WithDocs serves the OpenAPI document, the docs page and the JSON schemas
// on both surfaces. Off by default. gen-oas is unaffected either way: it
// reads Surface.API.OpenAPI() in-process, which never depends on the routes.
func WithDocs(enabled bool) Option {
	return func(c *apiConfig) { c.docs = enabled }
}

// WithRegistrar contributes a Huma registrar to the public surface. The OIDC
// feature uses this; the registered routes move under the OIDC base path when
// one is configured.
func WithRegistrar(fn func(huma.API)) Option {
	return func(c *apiConfig) { c.registrars = append(c.registrars, fn) }
}

// WithAdminRegistrar contributes a Huma registrar to the admin surface. Routes
// registered through it are reachable only on the admin handler / listener
// and never appear in the public surface's mux or OpenAPI spec.
func WithAdminRegistrar(fn func(huma.API)) Option {
	return func(c *apiConfig) { c.adminRegistrars = append(c.adminRegistrars, fn) }
}

// WithBasePath mounts the OIDC surface under a URL path prefix — the path
// component of OIDC_ISSUER (e.g. "/idp"). Health probes stay at the root.
// Empty ⇒ root, the historical default.
func WithBasePath(p string) Option {
	return func(c *apiConfig) { c.basePath = p }
}

// Surface is one structurally isolated handler tree: a Huma API for OpenAPI
// generation and the http.Handler that actually serves it. Prefix is the
// URL prefix the API's routes are mounted under (empty unless basePath is
// set on the public surface).
type Surface struct {
	API     huma.API
	Handler http.Handler
	Prefix  string
}

// Servers is the pair of Surfaces tempogate listens on. The serve command
// binds each to its own http.Server (and listener); a future-curious reader
// can verify the isolation by greping for any path between Public and Admin —
// there isn't one.
type Servers struct {
	Public *Surface
	Admin  *Surface
}

func New(readiness *Readiness, opts ...Option) *Servers {
	cfg := &apiConfig{}
	for _, o := range opts {
		o(cfg)
	}

	return &Servers{
		Public: newPublic(readiness, cfg),
		Admin:  newAdmin(cfg),
	}
}

func newPublic(readiness *Readiness, cfg *apiConfig) *Surface {
	mux := http.NewServeMux()

	// Root mode: one adapter, health + OIDC all at root.
	if cfg.basePath == "" {
		a := humago.NewWithPrefix(mux, "", cfg.humaConfig("tempogate"))
		registerHealth(a, readiness)
		for _, fn := range cfg.registrars {
			fn(a)
		}
		return &Surface{API: a, Handler: withSecurityHeaders(mux), Prefix: ""}
	}

	// Base-path mode: a minimal health adapter at the root (no OpenAPI/docs
	// surface — health is k8s-probe-only), and a full OIDC adapter under
	// basePath so the discovery document, the iss claim, and the served
	// routes stay in lockstep with no proxy StripPrefix.
	healthCfg := huma.DefaultConfig("tempogate", buildinfo.Version())
	withoutDocs(&healthCfg)
	healthAPI := humago.NewWithPrefix(mux, "", healthCfg)
	registerHealth(healthAPI, readiness)

	oidcAPI := humago.NewWithPrefix(mux, cfg.basePath, cfg.humaConfig("tempogate"))
	for _, fn := range cfg.registrars {
		fn(oidcAPI)
	}

	return &Surface{API: oidcAPI, Handler: withSecurityHeaders(mux), Prefix: cfg.basePath}
}

func newAdmin(cfg *apiConfig) *Surface {
	mux := http.NewServeMux()
	a := humago.NewWithPrefix(mux, "", cfg.humaConfig("tempogate-admin"))
	registerAdminHealth(a)
	for _, fn := range cfg.adminRegistrars {
		fn(a)
	}
	return &Surface{API: a, Handler: withSecurityHeaders(mux), Prefix: ""}
}

func (c *apiConfig) humaConfig(title string) huma.Config {
	hc := huma.DefaultConfig(title, buildinfo.Version())
	if !c.docs {
		withoutDocs(&hc)
	}
	return hc
}

// withoutDocs drops the routes that describe the API. It also drops Huma's
// create hooks, whose only entry is the schema-link transformer: it stamps
// a "$schema" URL into every response body that would point at the
// now-missing schemas route.
func withoutDocs(hc *huma.Config) {
	hc.OpenAPIPath = ""
	hc.DocsPath = ""
	hc.SchemasPath = ""
	hc.CreateHooks = nil
}
