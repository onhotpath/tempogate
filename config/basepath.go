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
