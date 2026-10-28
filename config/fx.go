package config

import (
	"time"

	"go.uber.org/fx"

	"github.com/onhotpath/tempogate/log"
)

// Result projects narrow values out of *Config so downstream packages can
// depend on the specific thing they need (log level, http listener) rather
// than the whole config struct.
type Result struct {
	fx.Out

	LogLevel              log.Level
	LogFormat             log.Format
	LogRequests           bool          `name:"log_requests"`
	HTTPListener          Listener      `name:"http"`
	AdminListener         Listener      `name:"admin"`
	HTTPServer            ServerConfig  `name:"http_server"`
	APIDocsEnabled        bool          `name:"api_docs_enabled"`
	HTTPTrustedProxies    string        `name:"http_trusted_proxies"`
	RateLimitAuthorize    int           `name:"http_rate_limit_authorize"`
	RateLimitDeviceAuthz  int           `name:"http_rate_limit_device_authorization"`
	RateLimitDeviceVerify int           `name:"http_rate_limit_device_verification"`
	RateLimitToken        int           `name:"http_rate_limit_token"`
	StateReaperInterval   time.Duration `name:"state_reaper_interval"`
	AdminTokenSHA256      string        `name:"admin_token_sha256"`
	AdminAllowedHosts     []string      `name:"admin_allowed_hosts"`
	AdminAllowSystemGrant bool          `name:"admin_allow_system_grants"`
	AdminKeysMaxTTL       time.Duration `name:"admin_keys_max_ttl"`
	KeysRetirementGrace   time.Duration `name:"keys_retirement_grace"`
	KeysReloadInterval    time.Duration `name:"keys_reload_interval"`
	KeysPublishDelay      time.Duration `name:"keys_publish_delay"`
	SqlitePath            string        `name:"sqlite_path"`
	SqliteMaxConns        int           `name:"sqlite_max_conns"`
	SqliteBusyTimeout     time.Duration `name:"sqlite_busy_timeout"`
	StateDriver           string        `name:"state_driver"`
	PostgresDSN           string        `name:"postgres_dsn"`
	PostgresDSNFile       string        `name:"postgres_dsn_file"`
	PostgresListenDSN     string        `name:"postgres_listen_dsn"`
	PostgresMaxConns      int           `name:"postgres_max_conns"`
	PostgresConnIdle      time.Duration `name:"postgres_conn_max_idle_time"`
	PostgresAllowInsecure bool          `name:"postgres_allow_insecure_sslmode"`
	OIDCIssuer            string        `name:"oidc_issuer"`
	OIDCBasePath          string        `name:"oidc_base_path"`
	OIDCIssuerPlainHTTP   bool          `name:"oidc_issuer_plain_http"`
	OIDCClients           string        `name:"oidc_clients"`
	OIDCClientSecrets     string        `name:"oidc_client_secrets"`
	OIDCAllowInsecureURIs bool          `name:"oidc_allow_insecure_redirect_uris"`
	OIDCAllowedDomains    string        `name:"oidc_allowed_domains"`
	OIDCAllowedHDs        string        `name:"oidc_allowed_hosted_domains"`
	OIDCSessionTTL        time.Duration `name:"oidc_session_ttl"`
	OIDCSessionSigningKey string        `name:"oidc_session_signing_key"`
	OIDCAccessTokenTTL    time.Duration `name:"oidc_access_token_ttl"`
	OIDCAccessTokenAud    string        `name:"oidc_access_token_audience"`
	OIDCRefreshTokenTTL   time.Duration `name:"oidc_refresh_token_ttl"`
	OIDCRefreshMaxLife    time.Duration `name:"oidc_refresh_max_lifetime"`
	OIDCAuthzRules        []string      `name:"oidc_authz_rules"`
	OIDCAuthzDefault      string        `name:"oidc_authz_default_permissions"`
	GoogleClientID        string        `name:"google_client_id"`
	GoogleClientSecret    string        `name:"google_client_secret"`
	GoogleAuthEndpoint    string        `name:"google_auth_endpoint"`
	GoogleTokenEndpoint   string        `name:"google_token_endpoint"`
	GoogleIssuerURL       string        `name:"google_issuer_url"`
	KeysEncryptionKey     string        `name:"keys_encryption_key"`
	KeysEncryptionKeyFile string        `name:"keys_encryption_key_file"`
}

// Fx loads the configuration from the file named by an fx-supplied Path (see
// ProcessPath), else ./application.yaml, then the environment.
func Fx() fx.Option {
	return fx.Options(
		fx.Provide(New),
		fx.Provide(project),
		fx.Invoke(logSource),
	)
}

// Supply provides an already-resolved *Config and the same projections as Fx,
// for a sub-graph built after the root graph has loaded configuration (the
// server subcommands build theirs only when they run).
func Supply(cfg *Config) fx.Option {
	return fx.Options(
		fx.Supply(cfg),
		fx.Provide(project),
	)
}

func project(cfg *Config) Result {
	return Result{
		LogLevel:              log.Level(cfg.Log.Level),
		LogFormat:             cfg.Log.Format,
		LogRequests:           cfg.Log.Requests,
		HTTPListener:          cfg.HTTP.Listener,
		AdminListener:         cfg.Admin.Listener,
		HTTPServer:            cfg.Server,
		APIDocsEnabled:        cfg.API.DocsEnabled,
		HTTPTrustedProxies:    cfg.HTTP.TrustedProxies,
		RateLimitAuthorize:    cfg.HTTP.RateLimit.Authorize,
		RateLimitDeviceAuthz:  cfg.HTTP.RateLimit.DeviceAuthorization,
		RateLimitDeviceVerify: cfg.HTTP.RateLimit.DeviceVerification,
		RateLimitToken:        cfg.HTTP.RateLimit.Token,
		StateReaperInterval:   cfg.State.ReaperInterval,
		AdminTokenSHA256:      cfg.Admin.TokenSHA256,
		AdminAllowedHosts:     adminAllowedHosts(cfg.Admin),
		AdminAllowSystemGrant: cfg.Admin.AllowSystemGrants,
		AdminKeysMaxTTL:       cfg.Admin.Keys.MaxTTL,
		KeysRetirementGrace:   cfg.Keys.RetirementGrace,
		KeysReloadInterval:    cfg.Keys.ReloadInterval,
		KeysPublishDelay:      cfg.Keys.PublishDelay,
		SqlitePath:            cfg.State.Sqlite.Path,
		SqliteMaxConns:        cfg.State.Sqlite.MaxConns,
		SqliteBusyTimeout:     cfg.State.Sqlite.BusyTimeout,
		StateDriver:           cfg.State.Driver,
		PostgresDSN:           cfg.State.Postgres.DSN,
		PostgresDSNFile:       cfg.State.Postgres.DSNFile,
		PostgresListenDSN:     cfg.State.Postgres.ListenDSN,
		PostgresMaxConns:      cfg.State.Postgres.MaxConns,
		PostgresConnIdle:      cfg.State.Postgres.ConnMaxIdleTime,
		PostgresAllowInsecure: cfg.State.Postgres.AllowInsecureSSLMode,
		OIDCIssuer:            cfg.OIDC.Issuer,
		OIDCBasePath:          issuerBasePath(cfg.OIDC.Issuer),
		OIDCIssuerPlainHTTP:   issuerIsPlainHTTP(cfg.OIDC.Issuer),
		OIDCClients:           cfg.OIDC.Clients,
		OIDCClientSecrets:     cfg.OIDC.ClientSecrets,
		OIDCAllowInsecureURIs: cfg.OIDC.AllowInsecureRedirectURIs,
		OIDCAllowedDomains:    cfg.OIDC.AllowedDomains,
		OIDCAllowedHDs:        cfg.OIDC.AllowedHostedDomains,
		OIDCSessionTTL:        cfg.OIDC.SessionTTL,
		OIDCSessionSigningKey: cfg.OIDC.SessionSigningKey,
		OIDCAccessTokenTTL:    cfg.OIDC.AccessTokenTTL,
		OIDCAccessTokenAud:    cfg.OIDC.AccessTokenAudience,
		OIDCRefreshTokenTTL:   cfg.OIDC.RefreshTokenTTL,
		OIDCRefreshMaxLife:    cfg.OIDC.RefreshMaxLifetime,
		OIDCAuthzRules:        cfg.OIDC.Authz.Rules,
		OIDCAuthzDefault:      cfg.OIDC.Authz.DefaultPermissions,
		GoogleClientID:        cfg.OIDC.Google.ClientID,
		GoogleClientSecret:    cfg.OIDC.Google.ClientSecret,
		GoogleAuthEndpoint:    cfg.OIDC.Google.AuthEndpoint,
		GoogleTokenEndpoint:   cfg.OIDC.Google.TokenEndpoint,
		GoogleIssuerURL:       cfg.OIDC.Google.IssuerURL,
		KeysEncryptionKey:     cfg.Keys.EncryptionKey,
		KeysEncryptionKeyFile: cfg.Keys.EncryptionKeyFile,
	}
}
