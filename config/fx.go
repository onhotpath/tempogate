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
	SqlitePath            string        `name:"sqlite_path"`
	SqliteMaxConns        int           `name:"sqlite_max_conns"`
	SqliteBusyTimeout     time.Duration `name:"sqlite_busy_timeout"`
	OIDCIssuer            string        `name:"oidc_issuer"`
	OIDCBasePath          string        `name:"oidc_base_path"`
	OIDCClients           string        `name:"oidc_clients"`
	OIDCClientSecrets     string        `name:"oidc_client_secrets"`
	OIDCAllowedDomains    string        `name:"oidc_allowed_domains"`
	OIDCSessionTTL        time.Duration `name:"oidc_session_ttl"`
	OIDCSessionSigningKey string        `name:"oidc_session_signing_key"`
	GoogleClientID        string        `name:"google_client_id"`
	GoogleClientSecret    string        `name:"google_client_secret"`
	GoogleAuthEndpoint    string        `name:"google_auth_endpoint"`
	GoogleTokenEndpoint   string        `name:"google_token_endpoint"`
	GoogleIssuerURL       string        `name:"google_issuer_url"`
}

func Fx() fx.Option {
	return fx.Options(
		fx.Provide(New),
		fx.Provide(func(cfg *Config) Result {
			return Result{
				LogLevel:              log.Level(cfg.Log.Level),
				HTTPListener:          cfg.HTTP.Listener,
				AdminListener:         cfg.Admin.Listener,
				SqlitePath:            cfg.State.Sqlite.Path,
				SqliteMaxConns:        cfg.State.Sqlite.MaxConns,
				SqliteBusyTimeout:     cfg.State.Sqlite.BusyTimeout,
				OIDCIssuer:            cfg.OIDC.Issuer,
				OIDCBasePath:          issuerBasePath(cfg.OIDC.Issuer),
				OIDCClients:           cfg.OIDC.Clients,
				OIDCClientSecrets:     cfg.OIDC.ClientSecrets,
				OIDCAllowedDomains:    cfg.OIDC.AllowedDomains,
				OIDCSessionTTL:        cfg.OIDC.SessionTTL,
				OIDCSessionSigningKey: cfg.OIDC.SessionSigningKey,
				GoogleClientID:        cfg.OIDC.Google.ClientID,
				GoogleClientSecret:    cfg.OIDC.Google.ClientSecret,
				GoogleAuthEndpoint:    cfg.OIDC.Google.AuthEndpoint,
				GoogleTokenEndpoint:   cfg.OIDC.Google.TokenEndpoint,
				GoogleIssuerURL:       cfg.OIDC.Google.IssuerURL,
			}
		}),
	)
}
