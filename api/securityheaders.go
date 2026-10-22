package api

import "net/http"

// defaultContentSecurityPolicy fits every response that does not set its own
// policy: JSON, redirects and plain error pages load nothing. Pages that do
// load something (the device UI, Huma's docs page) replace it with their own
// header; frame-ancestors 'none' must survive that replacement.
const defaultContentSecurityPolicy = "default-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

// withSecurityHeaders sets the listener-wide security headers before the
// handler runs, so a handler can still override one with Header().Set. It
// wraps the whole mux rather than being a Huma middleware so that mux 404s
// and Huma's non-operation routes (docs, spec, schemas) get the headers too.
//
// The anti-framing pair has to be a header: browsers ignore frame-ancestors
// in a <meta> CSP, and X-Frame-Options covers browsers without CSP level 2.
// HSTS is left to the TLS-terminating proxy, which knows whether the origin
// is HTTPS-only.
func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", defaultContentSecurityPolicy)
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}
