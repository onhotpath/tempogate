package config

import (
	"time"
)

type Config struct {
	Log   LogConfig   `ferry:"log"`
	HTTP  HTTPConfig  `ferry:"http"`
	Admin AdminConfig `ferry:"admin"`
	State StateConfig `ferry:"state"`
	OIDC  OIDCConfig  `ferry:"oidc"`
}

type LogConfig struct {
	Level string `ferry:"level"`
}

type HTTPConfig struct {
	Listener Listener `ferry:"listener"`
}

// AdminConfig configures the private admin listener. It is intentionally a
// separate bind from HTTPConfig: the admin Huma API is mounted on its own
// http.Server so the public listener never has handlers for /admin/*. Defaults
// to a loopback bind so a mis-deployment fails closed (admin unreachable from
// the pod's service IP unless explicitly opted into a cluster-internal bind).
type AdminConfig struct {
	Listener Listener `ferry:"listener"`
}

type StateConfig struct {
	Sqlite SqliteConfig `ferry:"sqlite"`
}

type SqliteConfig struct {
	Path        string        `ferry:"path"`
	MaxConns    int           `ferry:"max_conns"`
	BusyTimeout time.Duration `ferry:"busy_timeout"`
}

// OIDCConfig carries the externally reachable identity of this server and the
// upstream Google IdP it federates to. Issuer is the base URL relying parties
// (Temporal Web UI, frontend) use to reach tempogate; the discovery doc's
// jwks_uri is derived from it.
type OIDCConfig struct {
	Issuer string `ferry:"issuer"`

	// Clients is the v1 client registry: a comma-separated list of
	// "id:redirect_uri_prefix" entries. The first ':' splits id from prefix,
	// so the prefix may itself contain a scheme (e.g. "ui:https://x/cb").
	// Every client declared here is public: PKCE is mandatory.
	Clients string `ferry:"clients"`

	// ClientSecrets is the deliberately-separate opt-in for the confidential
	// PKCE carve-out: a comma-separated list of "id:secret" for clients in
	// Clients that authenticate at /token with a shared secret and do not
	// implement PKCE (e.g. the Temporal Web UI). Keeping it out of CLIENTS
	// makes the relaxation explicit and auditable; an entry for an
	// unregistered id fails fast. Empty ⇒ every client stays public. See
	// docs/pkce-and-confidential-clients.md.
	ClientSecrets string `ferry:"client_secrets"`

	// AllowedDomains is the v1 flat-authz gate: a comma-separated list of
	// email domains (e.g. "example.com,corp.example.org"). The callback
	// admits a Google identity only when its email domain matches one of
	// these exactly. Empty means no one is allowed.
	AllowedDomains string `ferry:"allowed_domains"`

	// SessionTTL bounds how long the first-party verification-page session
	// (the signed cookie that authenticates the human on the device-flow
	// approval UI) may live. Defaults to 5 minutes; operators may shorten
	// or lengthen via OIDC_SESSION_TTL to match risk posture.
	SessionTTL time.Duration `ferry:"session_ttl"`

	// SessionSigningKey is the base64url-encoded 32-byte HMAC-SHA256 key the
	// verification-page cookie's MAC is computed under. It is required only
	// for surfaces that mint or verify the cookie; consumers fail graph
	// construction at startup if it is missing or the wrong length.
	SessionSigningKey string `ferry:"session_signing_key"`

	Google GoogleConfig `ferry:"google"`
}

// GoogleConfig is the upstream OAuth2/OIDC client tempogate uses against
// Google. AuthEndpoint, TokenEndpoint and IssuerURL are all overridable so
// the end-to-end test can point the whole flow at a mock IdP.
type GoogleConfig struct {
	ClientID     string `ferry:"client_id"`
	ClientSecret string `ferry:"client_secret"`
	AuthEndpoint string `ferry:"auth_endpoint"`

	// TokenEndpoint is where the callback exchanges the authorization code
	// for Google's id_token.
	TokenEndpoint string `ferry:"token_endpoint"`

	// IssuerURL is the expected `iss` of Google's id_token and the base for
	// OIDC discovery (JWKS). The callback verifies the id_token signature
	// against the JWKS published under this issuer.
	IssuerURL string `ferry:"issuer_url"`
}
