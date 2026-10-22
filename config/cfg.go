package config

import (
	"time"
)

type Config struct {
	Log    LogConfig    `ferry:"log"`
	HTTP   HTTPConfig   `ferry:"http"`
	Admin  AdminConfig  `ferry:"admin"`
	Server ServerConfig `ferry:"server"`
	API    APIConfig    `ferry:"api"`
	State  StateConfig  `ferry:"state"`
	OIDC   OIDCConfig   `ferry:"oidc"`
	Keys   KeysConfig   `ferry:"keys"`
}

type LogConfig struct {
	Level string `ferry:"level"`

	// Requests emits one structured line per HTTP request on both listeners
	// (method, path without query, status, duration, bytes, remote address,
	// user agent, request id). On by default: tempogate is an auth server and
	// its access log is the audit trail. Probe and scrape paths log at debug.
	Requests bool `ferry:"requests"`
}

type HTTPConfig struct {
	Listener Listener `ferry:"listener"`

	// TrustedProxies (HTTP_TRUSTED_PROXIES) is a comma-separated list of
	// CIDRs or addresses of reverse proxies in front of tempogate. Only a
	// request whose TCP peer is in this set has its client address taken
	// from X-Forwarded-For; any other peer's header is ignored, so a client
	// cannot pick its own rate-limit bucket. Empty (the default) trusts no
	// proxy: behind an ingress every client then shares the ingress's
	// bucket.
	TrustedProxies string `ferry:"trusted_proxies"`

	RateLimit RateLimitConfig `ferry:"rate_limit"`
}

// RateLimitConfig caps how many requests one client address may send to
// each unauthenticated endpoint that writes state or checks a credential,
// per minute (as a burst that refills evenly). 0 disables that endpoint's
// limit, e.g. when a fronting proxy already rate-limits.
type RateLimitConfig struct {
	Authorize           int `ferry:"authorize"`
	DeviceAuthorization int `ferry:"device_authorization"`
	// DeviceVerification limits POST /device, the user_code entry form.
	DeviceVerification int `ferry:"device_verification"`
	Token              int `ferry:"token"`
}

// AdminConfig configures the private admin listener. It is intentionally a
// separate bind from HTTPConfig: the admin Huma API is mounted on its own
// http.Server so the public listener never has handlers for /admin/*. Defaults
// to a loopback bind so a mis-deployment fails closed (admin unreachable from
// the pod's service IP unless explicitly opted into a cluster-internal bind).
type AdminConfig struct {
	Listener Listener `ferry:"listener"`

	// TokenSHA256 is a comma-separated list of hex SHA-256 digests of the
	// bearer tokens the admin API accepts. Only digests are configured so the
	// tokens never sit in env or yaml; a list lets operators rotate without
	// downtime. Empty locks every /admin/* route except /admin/healthz.
	// Parsed and validated by the admin package when the server graph is
	// built, so commands that never serve the admin API ignore it.
	TokenSHA256 string `ferry:"token_sha256"`

	// AllowedHosts is a comma-separated list of host[:port] values the admin
	// API accepts in the Host header; an entry without a port matches any
	// port. Empty derives loopback names from Listener's port. It defeats DNS
	// rebinding, so a non-loopback bind must name its hosts here.
	AllowedHosts string `ferry:"allowed_hosts"`

	// AllowSystemGrants permits minting keys for the temporal-system
	// namespace, which Temporal treats as cluster-wide. Off by default so a
	// leaked admin token cannot mint a cluster-admin key.
	AllowSystemGrants bool `ferry:"allow_system_grants"`

	Keys AdminKeysConfig `ferry:"keys"`
}

// AdminKeysConfig bounds the integration keys the admin API mints.
type AdminKeysConfig struct {
	// MaxTTL caps how far in the future a key's expires_at may lie.
	// Temporal honours only exp and JWKS, never tempogate's revocation list,
	// so this cap is the longest a leaked key can authorize at Temporal
	// unless its signing key is retired first.
	MaxTTL time.Duration `ferry:"max_ttl"`
}

// KeysConfig governs how signing keys are stored and their lifecycle.
type KeysConfig struct {
	// EncryptionKey (KEYS_ENCRYPTION_KEY) is a base64-encoded 32-byte
	// key-encryption key. When set, private signing keys are stored
	// AES-256-GCM encrypted under it; when unset they are stored as plain
	// PEM. Once a key is encrypted, tempogate cannot start without it.
	EncryptionKey string `ferry:"encryption_key"`

	// EncryptionKeyFile (KEYS_ENCRYPTION_KEY_FILE) reads EncryptionKey from
	// a file instead, e.g. a mounted Kubernetes Secret. Set at most one.
	EncryptionKeyFile string `ferry:"encryption_key_file"`

	// RetirementGrace is how long a retired signing key stays in JWKS and
	// keeps verifying, so tokens already in flight survive the relying
	// parties' JWKS refresh. After it, every token signed by that key stops
	// verifying, integration keys included.
	RetirementGrace time.Duration `ferry:"retirement_grace"`

	// ReloadInterval is how often serve re-reads keypairs from the state
	// store, so `tempogate keys generate|retire` run elsewhere take effect
	// without a restart.
	ReloadInterval time.Duration `ferry:"reload_interval"`

	// PublishDelay is how long a new signing key sits in JWKS before it
	// signs. Temporal looks a kid up only in the JWKS it last fetched and
	// never refetches on an unknown kid, so this must exceed Temporal's
	// jwtKeyProvider.refreshInterval plus ReloadInterval.
	PublishDelay time.Duration `ferry:"publish_delay"`
}

// APIConfig controls what the Huma APIs expose beyond their operations.
type APIConfig struct {
	// DocsEnabled serves the OpenAPI document, the docs page and the JSON
	// schemas on the public listener, never the admin one. Dev only: they
	// are an unauthenticated map of every endpoint, and the docs page needs
	// a looser CSP to load its renderer from a CDN, so serve refuses it
	// unless OIDC_ISSUER is plain http. Off by default.
	DocsEnabled bool `ferry:"docs_enabled"`
}

// ServerConfig hardens every HTTP listener (public and admin alike). Without
// these bounds a slow body, an idle keep-alive or an oversized header block
// pins a goroutine and a file descriptor indefinitely, and graceful shutdown
// waits on such clients forever. Zero durations disable the corresponding
// net/http timeout; zero MaxHeaderBytes falls back to the net/http 1 MiB.
type ServerConfig struct {
	ReadHeaderTimeout time.Duration `ferry:"read_header_timeout"`
	ReadTimeout       time.Duration `ferry:"read_timeout"`
	WriteTimeout      time.Duration `ferry:"write_timeout"`
	IdleTimeout       time.Duration `ferry:"idle_timeout"`
	MaxHeaderBytes    int           `ferry:"max_header_bytes"`

	// ShutdownTimeout is the grace in-flight requests get after SIGTERM
	// before their connections are force-closed; zero force-closes at once.
	ShutdownTimeout time.Duration `ferry:"shutdown_timeout"`
}

type StateConfig struct {
	Sqlite SqliteConfig `ferry:"sqlite"`

	// ReaperInterval (STATE_REAPER_INTERVAL) is how often `serve` deletes
	// expired rows. 0 disables the reaper.
	ReaperInterval time.Duration `ferry:"reaper_interval"`
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

	// AllowInsecureIssuer lets `serve` start with a plain-http Issuer on a
	// non-loopback host. Development only: see ValidateIssuer. Kept separate
	// from OIDC_ALLOW_INSECURE_REDIRECT_URIS so each relaxation is opted into
	// on its own.
	AllowInsecureIssuer bool `ferry:"allow_insecure_issuer"`

	// Clients is the v1 client registry: a comma-separated list of
	// "id:redirect_uri" entries. The first ':' splits id from URI, so the URI
	// keeps its scheme (e.g. "ui:https://x/cb"). Each URI is matched exactly
	// (loopback http://127.0.0.1/<path> and http://[::1]/<path> match any
	// port); repeat an id to register several. An empty URI ("id:")
	// registers a device-only client. Every client declared here is public:
	// PKCE is mandatory.
	Clients string `ferry:"clients"`

	// AllowInsecureRedirectURIs lets Clients register plain-http,
	// non-loopback redirect URIs. Dev only: for local stacks whose hosts
	// are http-only Docker names. Defaults to false.
	AllowInsecureRedirectURIs bool `ferry:"allow_insecure_redirect_uris"`

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

	// AllowedHostedDomains turns on Workspace mode: a comma-separated list of
	// Google Workspace hosted domains. When set, the Google id_token must
	// carry an `hd` claim in this list, in addition to email_verified and the
	// AllowedDomains email check, so a consumer Google account created for an
	// allowed address is refused. Empty keeps the email-suffix-only gate
	// (logged as a warning at startup).
	AllowedHostedDomains string `ferry:"allowed_hosted_domains"`

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

	// AccessTokenTTL is the lifetime of each minted access token.
	AccessTokenTTL time.Duration `ferry:"access_token_ttl"`

	// AccessTokenAudience is the aud of every access token, integration
	// keys included: the audience a Temporal frontend can be configured to
	// require (global.authorization.audience, Temporal v1.29.0+). ID tokens
	// are unaffected; their aud is the requesting client.
	AccessTokenAudience string `ferry:"access_token_audience"`

	// RefreshTokenTTL is the idle lifetime of each rotated refresh token: a
	// session that is not refreshed for this long ends.
	RefreshTokenTTL time.Duration `ferry:"refresh_token_ttl"`

	// RefreshMaxLifetime is the absolute session lifetime, counted from the
	// original sign-in and never extended by rotation. Deliberately not
	// named OIDC_SESSION_*: those keys configure the device-flow
	// verification-page session, not the token session.
	RefreshMaxLifetime time.Duration `ferry:"refresh_max_lifetime"`

	Authz AuthzConfig `ferry:"authz"`

	Google GoogleConfig `ferry:"google"`
}

// AuthzConfig maps a signed-in person to the Temporal permissions their
// access token carries (see package authz). Deny by default: a person no
// rule matches gets DefaultPermissions, and with none of those no token at
// all. `serve` refuses to start when both are empty.
type AuthzConfig struct {
	// Rules (OIDC_AUTHZ_RULES_0, OIDC_AUTHZ_RULES_1, ... or a YAML list) are
	// "<selector>=<namespace>:<role>[,...]" entries, the selector being
	// email:<address> or domain:<email domain>. Every matching rule applies;
	// a namespace named by several gets the highest role.
	Rules []string `ferry:"rules"`

	// DefaultPermissions (OIDC_AUTHZ_DEFAULT_PERMISSIONS) is a
	// comma-separated permission list for admitted people no rule matches.
	// temporal-system:admin restores the behaviour before rules existed.
	DefaultPermissions string `ferry:"default_permissions"`
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
