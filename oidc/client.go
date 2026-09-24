package oidc

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrUnknownClient is returned when a client_id is not in the registry.
	ErrUnknownClient = errors.New("oidc: unknown client_id")
	// ErrRedirectURINotAllowed is returned when a redirect_uri is empty or
	// does not fall under the client's registered prefix.
	ErrRedirectURINotAllowed = errors.New("oidc: redirect_uri not under registered prefix")
	// ErrUnknownClientSecret is returned by WithSecrets when a secret is
	// declared for a client_id that is not in the registry — a typo that
	// would otherwise silently leave a client public.
	ErrUnknownClientSecret = errors.New("oidc: client secret declared for unregistered client_id")
)

// Client is a registered downstream OAuth2/OIDC client.
//
// Secret is the seam for tempogate's PKCE posture. The default and strict
// case is a *public* client (Secret == ""): PKCE is mandatory, exactly as
// OAuth 2.1 / RFC 9700 require. A non-empty Secret marks an *older-style
// confidential client* — one that authenticates at the token endpoint with a
// shared secret and does not implement PKCE (the Temporal Web UI's OIDC
// client is the motivating example). Such a client, and only such a client,
// may omit PKCE; it must still authenticate its secret at /token, and PKCE is
// still enforced if it chooses to send a code_challenge. See
// docs/pkce-and-confidential-clients.md.
type Client struct {
	RedirectPrefix string
	Secret         string
}

// ClientRegistry is the v1 client allowlist: client_id → Client. There is no
// admin UI; it is populated once from OIDC_CLIENTS (and, for the confidential
// carve-out, OIDC_CLIENT_SECRETS).
type ClientRegistry map[string]Client

// ParseClientRegistry parses a comma-separated list of "id:redirect_uri_prefix"
// entries. Only the first ':' of an entry splits id from prefix, so the prefix
// keeps its scheme (e.g. "ui:https://app.example.com/cb"). Every client parsed
// here is public (no secret ⇒ PKCE mandatory); confidential clients are opted
// in afterwards via WithSecrets. An empty string yields an empty registry.
// Malformed or duplicate entries are an error so a misconfiguration fails fast
// at graph construction rather than per request.
func ParseClientRegistry(raw string) (ClientRegistry, error) {
	reg := ClientRegistry{}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		id, prefix, ok := strings.Cut(entry, ":")
		if !ok || id == "" || prefix == "" {
			return nil, fmt.Errorf("oidc: malformed client entry %q (want id:redirect_uri_prefix)", entry)
		}
		if _, dup := reg[id]; dup {
			return nil, fmt.Errorf("oidc: duplicate client_id %q in registry", id)
		}
		reg[id] = Client{RedirectPrefix: prefix}
	}
	return reg, nil
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

// Validate checks that clientID is registered and redirectURI falls under its
// registered prefix. It returns ErrUnknownClient or ErrRedirectURINotAllowed
// so callers can map each to the right OAuth2 error response.
func (r ClientRegistry) Validate(clientID, redirectURI string) error {
	c, ok := r[clientID]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownClient, clientID)
	}
	if redirectURI == "" || !strings.HasPrefix(redirectURI, c.RedirectPrefix) {
		return fmt.Errorf("%w: %s", ErrRedirectURINotAllowed, redirectURI)
	}
	return nil
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
	return subtle.ConstantTimeCompare([]byte(c.Secret), []byte(presented)) == 1
}
