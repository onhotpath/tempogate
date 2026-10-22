package config

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ValidateIssuer enforces https for OIDC_ISSUER. Relying parties fetch the
// discovery document and JWKS from the issuer, so over plain http anyone on
// the path can substitute signing keys. Plain http is accepted only for a
// loopback host, which never leaves the machine. The caller decides whether
// OIDC_ALLOW_INSECURE_ISSUER (development only) overrides the result.
func ValidateIssuer(issuer string) error {
	u, err := url.Parse(strings.TrimSpace(issuer))
	if err == nil {
		switch {
		case issuerIsPlainHTTP(issuer):
			if isLoopback(u.Hostname()) {
				return nil
			}
		case strings.EqualFold(u.Scheme, "https") && u.Host != "":
			return nil
		}
	}
	return fmt.Errorf("OIDC_ISSUER %q must use https (plain http is allowed only for "+
		"localhost, 127.0.0.0/8 and ::1); set OIDC_ALLOW_INSECURE_ISSUER=true to allow it "+
		"for development", issuer)
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
