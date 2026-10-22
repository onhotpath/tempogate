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
	HTTPListener          Listener      `name:"http"`
	AdminListener         Listener      `name:"admin"`
	APIDocsEnabled        bool          `name:"api_docs_enabled"`
	SqlitePath            string        `name:"sqlite_path"`
	SqliteMaxConns        int           `name:"sqlite_max_conns"`
	SqliteBusyTimeout     time.Duration `name:"sqlite_busy_timeout"`
	OIDCIssuer            string        `name:"oidc_issuer"`
	OIDCBasePath          string        `name:"oidc_base_path"`
	OIDCClients           string        `name:"oidc_clients"`
	OIDCClientSecrets     string        `name:"oidc_client_secrets"`
	OIDCAllowInsecureURIs bool          `name:"oidc_allow_insecure_redirect_uris"`
	OIDCAllowedDomains    string        `name:"oidc_allowed_domains"`
	OIDCSessionTTL        time.Duration `name:"oidc_session_ttl"`
	OIDCSessionSigningKey string        `name:"oidc_session_signing_key"`
	OIDCAccessTokenTTL    time.Duration `name:"oidc_access_token_ttl"`
	OIDCRefreshTokenTTL   time.Duration `name:"oidc_refresh_token_ttl"`
	OIDCRefreshMaxLife    time.Duration `name:"oidc_refresh_max_lifetime"`
	GoogleClientID        string        `name:"google_client_id"`
	GoogleClientSecret    string        `name:"google_client_secret"`
	GoogleAuthEndpoint    string        `name:"google_auth_endpoint"`
	GoogleTokenEndpoint   string        `name:"google_token_endpoint"`
	GoogleIssuerURL       string        `name:"google_issuer_url"`
	KeysEncryptionKey     string        `name:"keys_encryption_key"`
	KeysEncryptionKeyFile string        `name:"keys_encryption_key_file"`
}

func Fx() fx.Option {
	return fx.Options(
		fx.Provide(New),
		fx.Provide(func(cfg *Config) Result {
			return Result{
				LogLevel:              log.Level(cfg.Log.Level),
				HTTPListener:          cfg.HTTP.Listener,
				AdminListener:         cfg.Admin.Listener,
				APIDocsEnabled:        cfg.API.DocsEnabled,
				SqlitePath:            cfg.State.Sqlite.Path,
				SqliteMaxConns:        cfg.State.Sqlite.MaxConns,
				SqliteBusyTimeout:     cfg.State.Sqlite.BusyTimeout,
				OIDCIssuer:            cfg.OIDC.Issuer,
				OIDCBasePath:          issuerBasePath(cfg.OIDC.Issuer),
				OIDCClients:           cfg.OIDC.Clients,
				OIDCClientSecrets:     cfg.OIDC.ClientSecrets,
				OIDCAllowInsecureURIs: cfg.OIDC.AllowInsecureRedirectURIs,
				OIDCAllowedDomains:    cfg.OIDC.AllowedDomains,
				OIDCSessionTTL:        cfg.OIDC.SessionTTL,
				OIDCSessionSigningKey: cfg.OIDC.SessionSigningKey,
				OIDCAccessTokenTTL:    cfg.OIDC.AccessTokenTTL,
				OIDCRefreshTokenTTL:   cfg.OIDC.RefreshTokenTTL,
				OIDCRefreshMaxLife:    cfg.OIDC.RefreshMaxLifetime,
				GoogleClientID:        cfg.OIDC.Google.ClientID,
				GoogleClientSecret:    cfg.OIDC.Google.ClientSecret,
				GoogleAuthEndpoint:    cfg.OIDC.Google.AuthEndpoint,
				GoogleTokenEndpoint:   cfg.OIDC.Google.TokenEndpoint,
				GoogleIssuerURL:       cfg.OIDC.Google.IssuerURL,
				KeysEncryptionKey:     cfg.Keys.EncryptionKey,
				KeysEncryptionKeyFile: cfg.Keys.EncryptionKeyFile,
			}
		}),
	)
}
