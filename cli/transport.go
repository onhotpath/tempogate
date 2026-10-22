package cli

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// ErrInsecureIssuer is returned when the issuer is plain http to a host other
// than this machine. The CLI sends authorization codes, refresh tokens and
// access tokens to the issuer, and over plain http anyone on the path can read
// them, so this is refused unless the caller opts in with --insecure.
var ErrInsecureIssuer = errors.New("cli: issuer uses plain http to a non-loopback host")

// ErrUnsafeRedirect is returned when the issuer answers a CLI request with a
// redirect the CLI will not follow: to another host, or down to plain http
// that the issuer rule would refuse. A 307/308 re-sends the request body, and
// that body is a refresh token, an authorization code and PKCE verifier, or a
// device code.
var ErrUnsafeRedirect = errors.New("cli: refusing unsafe redirect from issuer")

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

// maxRedirects matches net/http's default limit, which a custom CheckRedirect
// otherwise drops.
const maxRedirects = 10

// guardRedirects returns a copy of client that refuses redirects the issuer
// rule would not allow as an issuer: any change of host, and any hop to plain
// http unless the target is loopback or insecure is set. Every CLI request is
// a POST to an endpoint derived from the issuer, which TempoGate never
// redirects, so a redirect at all is unusual; a same-host one (an http to
// https upgrade, a path rewrite at a proxy) is still followed. A host change is
// refused outright because a 307/308 re-sends the body, and the body carries a
// refresh token, an authorization code and verifier, or a device code to a
// party the user never named. The caller's client is not modified, and its own
// CheckRedirect still runs after these checks.
func guardRedirects(client *http.Client, insecure bool) *http.Client {
	guarded := *client
	next := client.CheckRedirect
	guarded.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		from := via[0].URL
		if !strings.EqualFold(req.URL.Hostname(), from.Hostname()) {
			return fmt.Errorf("%w: %s to %s changes host", ErrUnsafeRedirect, from.Redacted(), req.URL.Redacted())
		}
		if err := checkIssuer(req.URL.String(), insecure); err != nil {
			return fmt.Errorf("%w: %s to %s: %w", ErrUnsafeRedirect, from.Redacted(), req.URL.Redacted(), err)
		}
		if next != nil {
			return next(req, via)
		}
		if len(via) >= maxRedirects {
			return fmt.Errorf("cli: stopped after %d redirects", maxRedirects)
		}
		return nil
	}
	return &guarded
}
