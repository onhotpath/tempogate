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
	"go.uber.org/zap"

	"github.com/onhotpath/tempogate/api/requestid"
	"github.com/onhotpath/tempogate/observe"
	"github.com/onhotpath/tempogate/redact"
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
	// middlewares wrap every operation on the public OIDC API; feature
	// packages use them for cross-cutting request policy (rate limits).
	middlewares []func(huma.Context, func(huma.Context))
	// adminMiddlewares install Huma middleware on the admin API (the admin
	// package's auth guard). They run after /admin/healthz is registered
	// and before any admin registrar, so they wrap every admin route except
	// the liveness probe.
	adminMiddlewares []func(huma.API)
	// adminHandlers are plain http.Handlers mounted on the admin mux
	// outside Huma, so the admin guard does not cover them (Prometheus
	// /metrics). They still get the listener-wide security headers.
	adminHandlers []adminHandler
	basePath      string
	docs          bool
	// logger receives the detail of every 5xx the sanitizer hides from clients.
	logger *zap.Logger
	// tracer makes every request on either surface a trace; nil installs
	// nothing.
	tracer observe.Tracer
	// redaction is the process's redact.Set; each traced request gets a
	// child of it for the values its handlers declare.
	redaction *redact.Set
}

type adminHandler struct {
	pattern string
	handler http.Handler
}

type Option func(*apiConfig)

// WithDocs serves the OpenAPI document, the docs page and the JSON schemas
// on the public surface. Off by default. The admin surface never serves them:
// they would sit outside the admin guard. gen-oas is unaffected either way:
// it reads Surface.API.OpenAPI() in-process, which never depends on the
// routes.
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

// WithMiddleware adds a Huma middleware to the public OIDC API. Huma binds
// middlewares when an operation is registered, so these are installed
// before any registrar runs, whatever order the options arrive in.
func WithMiddleware(fn func(huma.Context, func(huma.Context))) Option {
	return func(c *apiConfig) { c.middlewares = append(c.middlewares, fn) }
}

// WithAdminMiddleware contributes an installer that adds middleware to the
// admin Huma API. Whatever order options are given in, installers run before
// the admin registrars, so a registrar cannot opt its routes out.
func WithAdminMiddleware(fn func(huma.API)) Option {
	return func(c *apiConfig) { c.adminMiddlewares = append(c.adminMiddlewares, fn) }
}

// WithAdminHandler mounts h on the admin surface's mux under pattern (an
// http.ServeMux pattern such as "GET /metrics"). It bypasses the admin
// guard: the admin listener's bind is its only access control, so mount
// nothing here that is not safe for anything that can reach that listener.
func WithAdminHandler(pattern string, h http.Handler) Option {
	return func(c *apiConfig) {
		c.adminHandlers = append(c.adminHandlers, adminHandler{pattern: pattern, handler: h})
	}
}

// WithBasePath mounts the OIDC surface under a URL path prefix — the path
// component of OIDC_ISSUER (e.g. "/idp"). Health probes stay at the root.
// Empty ⇒ root, the historical default.
func WithBasePath(p string) Option {
	return func(c *apiConfig) { c.basePath = p }
}

// WithLogger sets where 5xx details are logged. Defaults to a no-op logger.
func WithLogger(l *zap.Logger) Option {
	return func(c *apiConfig) { c.logger = l }
}

// WithTracer makes every request on both surfaces a trace rooted at its
// server span. Nil keeps the default: nothing installed.
func WithTracer(t observe.Tracer) Option {
	return func(c *apiConfig) { c.tracer = t }
}

// WithRedaction sets the process's redact.Set. Each traced request carries a
// child of it in its context, which the request's handlers declare their
// sensitive values into and which masks them in every span of the request.
func WithRedaction(s *redact.Set) Option {
	return func(c *apiConfig) { c.redaction = s }
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
	if cfg.logger == nil {
		cfg.logger = zap.NewNop()
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
		a.UseMiddleware(cfg.middlewares...)
		registerHealth(a, readiness)
		for _, fn := range cfg.registrars {
			fn(a)
		}
		return &Surface{API: a, Handler: cfg.wrap(surfacePublic, mux), Prefix: ""}
	}

	// Base-path mode: a minimal health adapter at the root (no OpenAPI/docs
	// surface — health is k8s-probe-only), and a full OIDC adapter under
	// basePath so the discovery document, the iss claim, and the served
	// routes stay in lockstep with no proxy StripPrefix.
	healthCfg := newHumaConfig("tempogate", cfg.logger)
	withoutDocs(&healthCfg)
	healthAPI := humago.NewWithPrefix(mux, "", healthCfg)
	registerHealth(healthAPI, readiness)

	oidcAPI := humago.NewWithPrefix(mux, cfg.basePath, cfg.humaConfig("tempogate"))
	oidcAPI.UseMiddleware(cfg.middlewares...)
	for _, fn := range cfg.registrars {
		fn(oidcAPI)
	}

	return &Surface{API: oidcAPI, Handler: cfg.wrap(surfacePublic, mux), Prefix: cfg.basePath}
}

func newAdmin(cfg *apiConfig) *Surface {
	mux := http.NewServeMux()
	// No docs routes, ever: Huma serves them outside the operation
	// middleware chain, so the admin guard below could not cover them.
	// `tempogate gen-oas --admin` emits the admin spec instead.
	hc := newHumaConfig("tempogate-admin", cfg.logger)
	withoutDocs(&hc)
	a := humago.NewWithPrefix(mux, "", hc)
	// Huma binds the middleware chain when an operation is registered, so
	// this order is what keeps the liveness probe open (probes cannot carry
	// the admin token or a predictable Host) and every other admin route
	// behind the guard.
	registerAdminHealth(a)
	for _, fn := range cfg.adminMiddlewares {
		fn(a)
	}
	for _, fn := range cfg.adminRegistrars {
		fn(a)
	}
	for _, h := range cfg.adminHandlers {
		mux.Handle(h.pattern, h.handler)
	}
	return &Surface{API: a, Handler: cfg.wrap(surfaceAdmin, mux), Prefix: ""}
}

// wrap applies the listener-wide middleware every surface shares. The
// request id is assigned outermost, so the request's span and every handler
// see the id the response carries.
func (c *apiConfig) wrap(surface string, mux *http.ServeMux) http.Handler {
	var h http.Handler = mux
	if c.tracer != nil {
		// Only spans read the request's Set today, so only a traced request
		// pays for one. A log scrubber would install it unconditionally.
		h = withRequestRedaction(c.redaction, traceRequests(c.tracer, surface, mux))
	}
	return requestid.Middleware(withSecurityHeaders(h))
}

// withRequestRedaction gives every request a child of process to declare its
// sensitive values into (redact.Declare).
func withRequestRedaction(process *redact.Set, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(redact.NewContext(r.Context(), process.Child())))
	})
}

func (c *apiConfig) humaConfig(title string) huma.Config {
	hc := newHumaConfig(title, c.logger)
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
