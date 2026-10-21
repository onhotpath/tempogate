package cli

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ErrInsecureIssuer is returned when the issuer is plain http to a host other
// than this machine. The CLI sends authorization codes, refresh tokens and
// access tokens to the issuer, and over plain http anyone on the path can read
// them, so this is refused unless the caller opts in with --insecure.
var ErrInsecureIssuer = errors.New("cli: issuer uses plain http to a non-loopback host")

// checkIssuer enforces the CLI's transport rule on the issuer every endpoint
// is derived from: https always, http only for a loopback host (traffic that
// never leaves the machine, e.g. a local dev server) or when insecure is set.
func checkIssuer(issuer string, insecure bool) error {
	u, err := url.Parse(issuer)
	if err != nil {
		return fmt.Errorf("cli: invalid issuer %q: %w", issuer, err)
	}
	if u.Host == "" {
		return fmt.Errorf("cli: invalid issuer %q: want an absolute https:// URL", issuer)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		if insecure || isLoopbackHost(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("%w: %s; use https, or pass --insecure if this is a trusted development network", ErrInsecureIssuer, issuer)
	default:
		return fmt.Errorf("cli: invalid issuer %q: scheme must be https", issuer)
	}
}

// isLoopbackHost reports whether host names this machine: "localhost" or a
// loopback IP literal (127.0.0.0/8, ::1). Unlike the server's redirect-URI
// rule, localhost counts here: the risk is the network path, and a hostile
// local resolver is already on the machine. Other names are not resolved.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
