package oidc

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
)

var (
	// ErrUnknownClient is returned when a client_id is not in the registry.
	ErrUnknownClient = errors.New("oidc: unknown client_id")
	// ErrUnauthorizedClient is returned when a registered client asks for a
	// grant its registration does not allow (e.g. a device-only client at
	// /authorize).
	ErrUnauthorizedClient = errors.New("oidc: client not authorized for this grant type")
	// ErrRedirectURINotAllowed is returned when a redirect_uri is empty or
	// does not match one of the client's registered redirect URIs.
	ErrRedirectURINotAllowed = errors.New("oidc: redirect_uri not registered for client")
	// ErrInvalidClientRegistration is returned by ParseClientRegistry for any
	// OIDC_CLIENTS entry that is not a well-formed registration, so a bad
	// value fails startup instead of widening what /authorize accepts.
	ErrInvalidClientRegistration = errors.New("oidc: invalid client registration")
	// ErrUnknownClientSecret is returned by WithSecrets when a secret is
	// declared for a client_id that is not in the registry — a typo that
	// would otherwise silently leave a client public.
	ErrUnknownClientSecret = errors.New("oidc: client secret declared for unregistered client_id")
)

// GrantType is an OAuth2 grant a client may use. Grants are derived from the
// registration shape rather than configured separately: a client with
// redirect URIs uses the authorization-code flow, a client registered with an
// empty value uses the device flow, and both may refresh.
type GrantType string

const (
	GrantTypeAuthorizationCode GrantType = "authorization_code"
	GrantTypeRefreshToken      GrantType = "refresh_token"
	GrantTypeDeviceCode        GrantType = grantDeviceCode
)

// Client is a registered downstream OAuth2/OIDC client.
//
// RedirectURIs are exact URIs (see ClientRegistry.Validate for the loopback
// exception); they are never prefixes. GrantTypes lists what the client may
// do and is what /authorize and /device_authorization consult.
//
// Secret is the seam for tempogate's PKCE posture. The default and strict
// case is a *public* client (Secret == ""): PKCE is mandatory, exactly as
// OAuth 2.1 / RFC 9700 require. A non-empty Secret marks an *older-style
// confidential client* — one that authenticates at the token endpoint with a
// shared secret and does not implement PKCE (the Temporal Web UI's OIDC
// client is the motivating example). Such a client, and only such a client,
// may omit PKCE; it always authenticates its secret at /token, and PKCE is
// enforced on top if it chooses to send a code_challenge. See
// docs/pkce-and-confidential-clients.md.
type Client struct {
	RedirectURIs []string
	GrantTypes   []GrantType
	Secret       string
}

// Allows reports whether the client's registration permits grant g.
func (c Client) Allows(g GrantType) bool {
	return slices.Contains(c.GrantTypes, g)
}

// ClientRegistry is the v1 client allowlist: client_id → Client. There is no
// admin UI; it is populated once from OIDC_CLIENTS (and, for the confidential
// carve-out, OIDC_CLIENT_SECRETS).
type ClientRegistry map[string]Client

type registryConfig struct {
	allowInsecure bool
}

// RegistryOption configures ParseClientRegistry.
type RegistryOption func(*registryConfig)

// AllowInsecureRedirectURIs permits plain-http, non-loopback redirect URIs
// (OIDC_ALLOW_INSECURE_REDIRECT_URIS). It exists for local stacks whose hosts
// are http-only Docker names; production must leave it off, because a code
// sent over http to a non-loopback host can be read off the network.
func AllowInsecureRedirectURIs(allow bool) RegistryOption {
	return func(c *registryConfig) { c.allowInsecure = allow }
}

// ParseClientRegistry parses a comma-separated list of "id:redirect_uri"
// entries. Only the first ':' of an entry splits id from URI, so the URI keeps
// its scheme. Repeating an id registers several URIs for that client. An empty
// URI ("tempogate-device:") registers a device-only client. Every client
// parsed here is public (no secret ⇒ PKCE mandatory); confidential clients
// are opted in afterwards via WithSecrets. An empty string yields an empty
// registry. Anything malformed or ambiguous is an error wrapping
// ErrInvalidClientRegistration so a misconfiguration fails fast at graph
// construction rather than per request.
func ParseClientRegistry(raw string, opts ...RegistryOption) (ClientRegistry, error) {
	cfg := &registryConfig{}
	for _, o := range opts {
		o(cfg)
	}

	reg := ClientRegistry{}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		id, uri, ok := strings.Cut(entry, ":")
		if !ok || id == "" {
			return nil, fmt.Errorf("%w: malformed entry %q (want id:redirect_uri, or id: for a device-only client)",
				ErrInvalidClientRegistration, entry)
		}
		c, seen := reg[id]
		deviceOnly := seen && len(c.RedirectURIs) == 0
		switch {
		case uri == "" && seen:
			return nil, fmt.Errorf("%w: client %q: a device-only entry (%q) cannot be combined with other entries for the same id",
				ErrInvalidClientRegistration, id, entry)
		case uri == "":
			reg[id] = Client{GrantTypes: []GrantType{GrantTypeDeviceCode, GrantTypeRefreshToken}}
			continue
		case deviceOnly:
			return nil, fmt.Errorf("%w: client %q: a device-only entry (%q) cannot be combined with redirect URI entries",
				ErrInvalidClientRegistration, id, id+":")
		case slices.Contains(c.RedirectURIs, uri):
			return nil, fmt.Errorf("%w: client %q: duplicate redirect URI %q", ErrInvalidClientRegistration, id, uri)
		}
		if err := checkRegisteredRedirectURI(uri, cfg.allowInsecure); err != nil {
			return nil, fmt.Errorf("%w: client %q: redirect URI %q %s", ErrInvalidClientRegistration, id, uri, err)
		}
		c.RedirectURIs = append(c.RedirectURIs, uri)
		c.GrantTypes = []GrantType{GrantTypeAuthorizationCode, GrantTypeRefreshToken}
		reg[id] = c
	}
	return reg, nil
}

// checkRegisteredRedirectURI enforces that a registration is one exact,
// absolute URI. The prefix-shaped values the old format invited
// ("http://127.0.0.1:", "https://host") are exactly what made prefix matching
// exploitable, so they are refused with a message pointing at the fix.
func checkRegisteredRedirectURI(raw string, allowInsecure bool) error {
	u, err := parseRedirectURI(raw)
	if err != nil {
		return err
	}
	if u.Path == "" {
		return errors.New("has no path; register the full callback URI, not a prefix")
	}
	if isLoopback(u) {
		if u.Port() != "" {
			return errors.New("is a loopback URI with a port; omit the port (any port is accepted for loopback, RFC 8252 §7.3)")
		}
		if u.RawQuery != "" || u.ForceQuery {
			return errors.New("is a loopback URI with a query; loopback registrations must not carry one")
		}
		return nil
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && allowInsecure:
	case u.Scheme == "http":
		return errors.New("must use https (set OIDC_ALLOW_INSECURE_REDIRECT_URIS=true for a local plain-http stack only)")
	default:
		return fmt.Errorf("has unsupported scheme %q (want https)", u.Scheme)
	}
	return nil
}

// parseRedirectURI applies the structural rules every redirect URI must meet,
// both at registration and per request (RFC 9700 §2.1, RFC 6749 §3.1.2):
// absolute, a host, no userinfo (which lets "trusted@evil" point anywhere),
// no fragment, and no empty port (the trailing ':' of the old prefix form).
func parseRedirectURI(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("does not parse as a URI")
	}
	switch {
	case !u.IsAbs() || u.Opaque != "":
		return nil, errors.New("is not an absolute URI")
	case u.Host == "":
		return nil, errors.New("has no host")
	case strings.HasSuffix(u.Host, ":"):
		return nil, errors.New("ends its host with ':'; register the full callback URI, not a prefix")
	case u.User != nil:
		return nil, errors.New("must not contain userinfo")
	case strings.Contains(raw, "#"):
		return nil, errors.New("must not contain a fragment")
	}
	return u, nil
}

// isLoopback reports whether u is in the RFC 8252 §7.3 loopback class. Only
// the literal IP hosts qualify: "localhost" can be re-pointed by DNS or the
// hosts file, so it gets exact matching like any other host.
func isLoopback(u *url.URL) bool {
	if u.Scheme != "http" {
		return false
	}
	h := u.Hostname()
	return h == "127.0.0.1" || (h == "::1" && strings.HasPrefix(u.Host, "[::1]"))
}

// WithSecrets overlays confidential-client secrets onto an already-parsed
// registry from a comma-separated list of "id:secret" entries (first ':'
// splits, so the secret may contain ':'). It is deliberately a separate
// source from OIDC_CLIENTS: the redirect allowlist stays the primary,
// always-present config, and the PKCE carve-out is an explicit, auditable
// opt-in. A secret for an unregistered client_id, a duplicate, or an empty
// id/secret is an error so the relaxation can never be enabled by accident.
func (r ClientRegistry) WithSecrets(raw string) error {
	seen := map[string]struct{}{}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		id, secret, ok := strings.Cut(entry, ":")
		if !ok || id == "" || secret == "" {
			return fmt.Errorf("oidc: malformed client secret entry %q (want id:secret)", entry)
		}
		if _, dup := seen[id]; dup {
			return fmt.Errorf("oidc: duplicate client secret for %q", id)
		}
		c, ok := r[id]
		if !ok {
			return fmt.Errorf("%w: %s", ErrUnknownClientSecret, id)
		}
		seen[id] = struct{}{}
		c.Secret = secret
		r[id] = c
	}
	return nil
}

// Validate checks that clientID is registered for the authorization-code
// flow and that redirectURI matches one of its registered URIs. It returns
// ErrUnknownClient, ErrUnauthorizedClient or ErrRedirectURINotAllowed so
// callers can map each to the right OAuth2 error response.
//
// Matching is exact string comparison, with no normalization: case,
// percent-encoding, trailing slashes and dot segments all have to match the
// registration byte for byte, so nothing an attacker appends can still pass.
// The one exception is the RFC 8252 §7.3 loopback class, where the port is
// chosen at runtime by the native app: there scheme, host, path and the
// (empty) query must match exactly and only the port is free.
func (r ClientRegistry) Validate(clientID, redirectURI string) error {
	c, ok := r[clientID]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownClient, clientID)
	}
	if !c.Allows(GrantTypeAuthorizationCode) {
		return fmt.Errorf("%w: %s", ErrUnauthorizedClient, clientID)
	}
	if !c.matchRedirectURI(redirectURI) {
		return fmt.Errorf("%w: %s", ErrRedirectURINotAllowed, redirectURI)
	}
	return nil
}

func (c Client) matchRedirectURI(raw string) bool {
	if raw == "" {
		return false
	}
	if slices.Contains(c.RedirectURIs, raw) {
		return true
	}
	req, err := parseRedirectURI(raw)
	if err != nil || !isLoopback(req) || strings.HasSuffix(req.Host, ":") {
		return false
	}
	// Re-serializing must reproduce the input byte for byte; otherwise the
	// request relied on an encoding the parser normalized away (e.g. a
	// percent-encoded host or path), which exact matching refuses.
	if req.String() != raw || req.RawQuery != "" || req.ForceQuery {
		return false
	}
	for _, reg := range c.RedirectURIs {
		u, err := url.Parse(reg)
		if err != nil || !isLoopback(u) {
			continue
		}
		if req.Scheme == u.Scheme && req.Hostname() == u.Hostname() && req.EscapedPath() == u.EscapedPath() {
			return true
		}
	}
	return false
}

// Lookup returns the registration for clientID, if any.
func (r ClientRegistry) Lookup(clientID string) (Client, bool) {
	c, ok := r[clientID]
	return c, ok
}

// IsConfidential reports whether clientID is a registered confidential client
// (has a secret). Only a confidential client is permitted to complete the
// authorization-code flow without PKCE; /authorize consults this to decide
// whether a missing code_challenge is acceptable.
func (r ClientRegistry) IsConfidential(clientID string) bool {
	c, ok := r[clientID]
	return ok && c.Secret != ""
}

// Authenticate verifies a client secret presented at the token endpoint. It
// returns true only for a registered confidential client whose secret matches
// in constant time. A public client, an unknown client, or an empty presented
// secret always fails — so the PKCE carve-out can never degrade into "no PKCE
// and no client authentication".
func (r ClientRegistry) Authenticate(clientID, presented string) bool {
	c, ok := r[clientID]
	if !ok || c.Secret == "" || presented == "" {
		return false
	}
	// Comparing fixed-length digests keeps the compare constant-time in the
	// secret's length too, which ConstantTimeCompare on the raw values is not.
	want := sha256.Sum256([]byte(c.Secret))
	got := sha256.Sum256([]byte(presented))
	return subtle.ConstantTimeCompare(want[:], got[:]) == 1
}
