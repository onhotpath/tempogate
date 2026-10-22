package config

import (
	"net/url"
	"strings"
)

// issuerBasePath extracts the URL path component of OIDC_ISSUER — the single
// source of truth for where tempogate mounts its OIDC surface. It is
// normalised the same way api/wellknown.go and oidc.New already normalise the
// issuer (strings.TrimRight(…, "/")): a leading slash, no trailing slash, and
// "" for a root issuer (the historical, zero-regression default).
//
// A blank or unparseable issuer (no scheme/host) yields "" — base-path mode is
// simply off; serve-time issuer validation lives elsewhere and is not this
// projection's concern.
func issuerBasePath(issuer string) string {
	u, err := url.Parse(strings.TrimSpace(issuer))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return strings.TrimRight(u.Path, "/")
}

// issuerIsPlainHTTP reports whether OIDC_ISSUER is served over plain http,
// which only a local or docker-compose dev stack does. Anything else, an
// unparseable issuer included, counts as a real deployment: the session
// cookie stays Secure and serve refuses API_DOCS_ENABLED.
func issuerIsPlainHTTP(issuer string) bool {
	u, err := url.Parse(strings.TrimSpace(issuer))
	return err == nil && strings.EqualFold(u.Scheme, "http")
}
