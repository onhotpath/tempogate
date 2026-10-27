package config

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"go.uber.org/fx"

	"github.com/onhotpath/tempogate/log"
)

type ConfigSuite struct {
	suite.Suite
}

var defaultRateLimits = RateLimitConfig{Authorize: 30, DeviceAuthorization: 10, DeviceVerification: 20, Token: 60}

func TestConfigSuite(t *testing.T) {
	suite.Run(t, new(ConfigSuite))
}

// wantDefaultServer pins the HTTP server hardening defaults shared by the
// public and admin listeners.
var wantDefaultServer = ServerConfig{
	ReadHeaderTimeout: 10 * time.Second,
	ReadTimeout:       15 * time.Second,
	WriteTimeout:      30 * time.Second,
	IdleTimeout:       60 * time.Second,
	MaxHeaderBytes:    16 << 10,
	ShutdownTimeout:   15 * time.Second,
}

// wantDefaultPostgres pins the Postgres pool defaults, unused while
// STATE_DRIVER is sqlite.
var wantDefaultPostgres = PostgresConfig{MaxConns: 10, ConnMaxIdleTime: 30 * time.Minute}

func (s *ConfigSuite) TestNew() {
	cases := []struct {
		name string
		env  map[string]string
		want *Config
	}{
		{
			name: "defaults",
			want: &Config{
				Log: LogConfig{Level: "info", Format: log.FormatAuto, Requests: true},
				HTTP: HTTPConfig{
					Listener: Listener{
						IP:   net.IPv4(127, 0, 0, 1),
						Port: 8000,
					},
					RateLimit: defaultRateLimits,
				},
				Admin: AdminConfig{
					Listener: Listener{
						IP:   net.IPv4(127, 0, 0, 1),
						Port: 8081,
					},
					Keys: AdminKeysConfig{MaxTTL: 90 * 24 * time.Hour},
				},
				Keys: KeysConfig{
					RetirementGrace: 4 * time.Hour,
					ReloadInterval:  30 * time.Second,
					PublishDelay:    5 * time.Minute,
				},
				Server: wantDefaultServer,
				State: StateConfig{
					Driver:   StateDriverSQLite,
					Postgres: wantDefaultPostgres,
					Sqlite: SqliteConfig{
						Path:        "/var/lib/tempogate/state.db",
						MaxConns:    1,
						BusyTimeout: 5 * time.Second,
					},
					ReaperInterval: 5 * time.Minute,
				},
				OIDC: OIDCConfig{
					Issuer:              "http://127.0.0.1:8000",
					SessionTTL:          5 * time.Minute,
					AccessTokenTTL:      4 * time.Hour,
					AccessTokenAudience: "temporal",
					RefreshTokenTTL:     7 * 24 * time.Hour,
					RefreshMaxLifetime:  7 * 24 * time.Hour,
					Google: GoogleConfig{
						AuthEndpoint:  "https://accounts.google.com/o/oauth2/v2/auth",
						TokenEndpoint: "https://oauth2.googleapis.com/token",
						IssuerURL:     "https://accounts.google.com",
					},
				},
			},
		},
		{
			name: "log, request logging and http overridden by env",
			env: map[string]string{
				"LOG_LEVEL":     "debug",
				"LOG_FORMAT":    "json",
				"LOG_REQUESTS":  "false",
				"HTTP_LISTENER": "0.0.0.0:9000",
			},
			want: &Config{
				Log: LogConfig{Level: "debug", Format: log.FormatJSON},
				HTTP: HTTPConfig{
					Listener: Listener{
						IP:   net.IPv4(0, 0, 0, 0),
						Port: 9000,
					},
					RateLimit: defaultRateLimits,
				},
				Admin: AdminConfig{
					Listener: Listener{
						IP:   net.IPv4(127, 0, 0, 1),
						Port: 8081,
					},
					Keys: AdminKeysConfig{MaxTTL: 90 * 24 * time.Hour},
				},
				Keys: KeysConfig{
					RetirementGrace: 4 * time.Hour,
					ReloadInterval:  30 * time.Second,
					PublishDelay:    5 * time.Minute,
				},
				Server: wantDefaultServer,
				State: StateConfig{
					Driver:   StateDriverSQLite,
					Postgres: wantDefaultPostgres,
					Sqlite: SqliteConfig{
						Path:        "/var/lib/tempogate/state.db",
						MaxConns:    1,
						BusyTimeout: 5 * time.Second,
					},
					ReaperInterval: 5 * time.Minute,
				},
				OIDC: OIDCConfig{
					Issuer:              "http://127.0.0.1:8000",
					SessionTTL:          5 * time.Minute,
					AccessTokenTTL:      4 * time.Hour,
					AccessTokenAudience: "temporal",
					RefreshTokenTTL:     7 * 24 * time.Hour,
					RefreshMaxLifetime:  7 * 24 * time.Hour,
					Google: GoogleConfig{
						AuthEndpoint:  "https://accounts.google.com/o/oauth2/v2/auth",
						TokenEndpoint: "https://oauth2.googleapis.com/token",
						IssuerURL:     "https://accounts.google.com",
					},
				},
			},
		},
		{
			name: "token lifetimes overridden by env",
			env: map[string]string{
				"OIDC_ACCESS_TOKEN_TTL":      "30m",
				"OIDC_ACCESS_TOKEN_AUDIENCE": "temporal-prod",
				"OIDC_REFRESH_TOKEN_TTL":     "24h",
				"OIDC_REFRESH_MAX_LIFETIME":  "336h",
			},
			want: &Config{
				Log: LogConfig{Level: "info", Format: log.FormatAuto, Requests: true},
				HTTP: HTTPConfig{
					Listener: Listener{
						IP:   net.IPv4(127, 0, 0, 1),
						Port: 8000,
					},
					RateLimit: defaultRateLimits,
				},
				Admin: AdminConfig{
					Listener: Listener{
						IP:   net.IPv4(127, 0, 0, 1),
						Port: 8081,
					},
					Keys: AdminKeysConfig{MaxTTL: 90 * 24 * time.Hour},
				},
				Keys: KeysConfig{
					RetirementGrace: 4 * time.Hour,
					ReloadInterval:  30 * time.Second,
					PublishDelay:    5 * time.Minute,
				},
				Server: wantDefaultServer,
				State: StateConfig{
					Driver:   StateDriverSQLite,
					Postgres: wantDefaultPostgres,
					Sqlite: SqliteConfig{
						Path:        "/var/lib/tempogate/state.db",
						MaxConns:    1,
						BusyTimeout: 5 * time.Second,
					},
					ReaperInterval: 5 * time.Minute,
				},
				OIDC: OIDCConfig{
					Issuer:              "http://127.0.0.1:8000",
					SessionTTL:          5 * time.Minute,
					AccessTokenTTL:      30 * time.Minute,
					AccessTokenAudience: "temporal-prod",
					RefreshTokenTTL:     24 * time.Hour,
					RefreshMaxLifetime:  14 * 24 * time.Hour,
					Google: GoogleConfig{
						AuthEndpoint:  "https://accounts.google.com/o/oauth2/v2/auth",
						TokenEndpoint: "https://oauth2.googleapis.com/token",
						IssuerURL:     "https://accounts.google.com",
					},
				},
			},
		},
		{
			name: "admin auth overridden by env",
			env: map[string]string{
				"ADMIN_TOKEN_SHA256":        "aa,bb",
				"ADMIN_ALLOWED_HOSTS":       "admin.internal:8081",
				"ADMIN_ALLOW_SYSTEM_GRANTS": "true",
			},
			want: func() *Config {
				c := defaultConfig()
				c.Admin.TokenSHA256 = "aa,bb"
				c.Admin.AllowedHosts = "admin.internal:8081"
				c.Admin.AllowSystemGrants = true
				return c
			}(),
		},
		{
			name: "authz rules and default from indexed env keys",
			env: map[string]string{
				"OIDC_AUTHZ_RULES_0":             "email:alice@example.com=orders:read",
				"OIDC_AUTHZ_RULES_1":             "domain:example.com=payments:write",
				"OIDC_AUTHZ_DEFAULT_PERMISSIONS": "temporal-system:admin",
			},
			want: func() *Config {
				c := defaultConfig()
				c.OIDC.Authz = AuthzConfig{
					Rules:              []string{"email:alice@example.com=orders:read", "domain:example.com=payments:write"},
					DefaultPermissions: "temporal-system:admin",
				}
				return c
			}(),
		},
		{
			name: "key lifetimes overridden by env",
			env: map[string]string{
				"ADMIN_KEYS_MAX_TTL":    "720h",
				"KEYS_RETIREMENT_GRACE": "1h",
				"KEYS_RELOAD_INTERVAL":  "5s",
				"KEYS_PUBLISH_DELAY":    "2m",
			},
			want: func() *Config {
				c := defaultConfig()
				c.Admin.Keys.MaxTTL = 720 * time.Hour
				c.Keys.RetirementGrace = time.Hour
				c.Keys.ReloadInterval = 5 * time.Second
				c.Keys.PublishDelay = 2 * time.Minute
				return c
			}(),
		},
		{
			name: "admin listener overridden by env",
			env: map[string]string{
				"ADMIN_LISTENER": "127.0.0.1:9091",
			},
			want: &Config{
				Log: LogConfig{Level: "info", Format: log.FormatAuto, Requests: true},
				HTTP: HTTPConfig{
					Listener: Listener{
						IP:   net.IPv4(127, 0, 0, 1),
						Port: 8000,
					},
					RateLimit: defaultRateLimits,
				},
				Admin: AdminConfig{
					Listener: Listener{
						IP:   net.IPv4(127, 0, 0, 1),
						Port: 9091,
					},
					Keys: AdminKeysConfig{MaxTTL: 90 * 24 * time.Hour},
				},
				Keys: KeysConfig{
					RetirementGrace: 4 * time.Hour,
					ReloadInterval:  30 * time.Second,
					PublishDelay:    5 * time.Minute,
				},
				Server: wantDefaultServer,
				State: StateConfig{
					Driver:   StateDriverSQLite,
					Postgres: wantDefaultPostgres,
					Sqlite: SqliteConfig{
						Path:        "/var/lib/tempogate/state.db",
						MaxConns:    1,
						BusyTimeout: 5 * time.Second,
					},
					ReaperInterval: 5 * time.Minute,
				},
				OIDC: OIDCConfig{
					Issuer:              "http://127.0.0.1:8000",
					SessionTTL:          5 * time.Minute,
					AccessTokenTTL:      4 * time.Hour,
					AccessTokenAudience: "temporal",
					RefreshTokenTTL:     7 * 24 * time.Hour,
					RefreshMaxLifetime:  7 * 24 * time.Hour,
					Google: GoogleConfig{
						AuthEndpoint:  "https://accounts.google.com/o/oauth2/v2/auth",
						TokenEndpoint: "https://oauth2.googleapis.com/token",
						IssuerURL:     "https://accounts.google.com",
					},
				},
			},
		},
		{
			name: "sqlite overridden by env",
			env: map[string]string{
				"STATE_SQLITE_PATH":         "/tmp/tempogate.db",
				"STATE_SQLITE_MAX_CONNS":    "8",
				"STATE_SQLITE_BUSY_TIMEOUT": "2s",
			},
			want: &Config{
				Log: LogConfig{Level: "info", Format: log.FormatAuto, Requests: true},
				HTTP: HTTPConfig{
					Listener: Listener{
						IP:   net.IPv4(127, 0, 0, 1),
						Port: 8000,
					},
					RateLimit: defaultRateLimits,
				},
				Admin: AdminConfig{
					Listener: Listener{
						IP:   net.IPv4(127, 0, 0, 1),
						Port: 8081,
					},
					Keys: AdminKeysConfig{MaxTTL: 90 * 24 * time.Hour},
				},
				Keys: KeysConfig{
					RetirementGrace: 4 * time.Hour,
					ReloadInterval:  30 * time.Second,
					PublishDelay:    5 * time.Minute,
				},
				Server: wantDefaultServer,
				State: StateConfig{
					Driver:   StateDriverSQLite,
					Postgres: wantDefaultPostgres,
					Sqlite: SqliteConfig{
						Path:        "/tmp/tempogate.db",
						MaxConns:    8,
						BusyTimeout: 2 * time.Second,
					},
					ReaperInterval: 5 * time.Minute,
				},
				OIDC: OIDCConfig{
					Issuer:              "http://127.0.0.1:8000",
					SessionTTL:          5 * time.Minute,
					AccessTokenTTL:      4 * time.Hour,
					AccessTokenAudience: "temporal",
					RefreshTokenTTL:     7 * 24 * time.Hour,
					RefreshMaxLifetime:  7 * 24 * time.Hour,
					Google: GoogleConfig{
						AuthEndpoint:  "https://accounts.google.com/o/oauth2/v2/auth",
						TokenEndpoint: "https://oauth2.googleapis.com/token",
						IssuerURL:     "https://accounts.google.com",
					},
				},
			},
		},
		{
			name: "postgres from env",
			env: map[string]string{
				"STATE_DRIVER":                          "postgres",
				"STATE_POSTGRES_DSN_FILE":               "/run/secrets/dsn",
				"STATE_POSTGRES_LISTEN_DSN":             "postgres://db:5432/tempogate?sslmode=verify-full",
				"STATE_POSTGRES_MAX_CONNS":              "20",
				"STATE_POSTGRES_CONN_MAX_IDLE_TIME":     "2m",
				"STATE_POSTGRES_ALLOW_INSECURE_SSLMODE": "true",
			},
			want: &Config{
				Log: LogConfig{Level: "info", Format: log.FormatAuto, Requests: true},
				HTTP: HTTPConfig{
					Listener: Listener{
						IP:   net.IPv4(127, 0, 0, 1),
						Port: 8000,
					},
					RateLimit: defaultRateLimits,
				},
				Admin: AdminConfig{
					Listener: Listener{
						IP:   net.IPv4(127, 0, 0, 1),
						Port: 8081,
					},
					Keys: AdminKeysConfig{MaxTTL: 90 * 24 * time.Hour},
				},
				Keys: KeysConfig{
					RetirementGrace: 4 * time.Hour,
					ReloadInterval:  30 * time.Second,
					PublishDelay:    5 * time.Minute,
				},
				Server: wantDefaultServer,
				State: StateConfig{
					Driver: StateDriverPostgres,
					Postgres: PostgresConfig{
						DSNFile:              "/run/secrets/dsn",
						ListenDSN:            "postgres://db:5432/tempogate?sslmode=verify-full",
						MaxConns:             20,
						ConnMaxIdleTime:      2 * time.Minute,
						AllowInsecureSSLMode: true,
					},
					Sqlite: SqliteConfig{
						Path:        "/var/lib/tempogate/state.db",
						MaxConns:    1,
						BusyTimeout: 5 * time.Second,
					},
					ReaperInterval: 5 * time.Minute,
				},
				OIDC: OIDCConfig{
					Issuer:              "http://127.0.0.1:8000",
					SessionTTL:          5 * time.Minute,
					AccessTokenTTL:      4 * time.Hour,
					AccessTokenAudience: "temporal",
					RefreshTokenTTL:     7 * 24 * time.Hour,
					RefreshMaxLifetime:  7 * 24 * time.Hour,
					Google: GoogleConfig{
						AuthEndpoint:  "https://accounts.google.com/o/oauth2/v2/auth",
						TokenEndpoint: "https://oauth2.googleapis.com/token",
						IssuerURL:     "https://accounts.google.com",
					},
				},
			},
		},
		{
			name: "oidc issuer overridden by env",
			env: map[string]string{
				"OIDC_ISSUER": "https://tempogate.internal.example.com",
			},
			want: &Config{
				Log: LogConfig{Level: "info", Format: log.FormatAuto, Requests: true},
				HTTP: HTTPConfig{
					Listener: Listener{
						IP:   net.IPv4(127, 0, 0, 1),
						Port: 8000,
					},
					RateLimit: defaultRateLimits,
				},
				Admin: AdminConfig{
					Listener: Listener{
						IP:   net.IPv4(127, 0, 0, 1),
						Port: 8081,
					},
					Keys: AdminKeysConfig{MaxTTL: 90 * 24 * time.Hour},
				},
				Keys: KeysConfig{
					RetirementGrace: 4 * time.Hour,
					ReloadInterval:  30 * time.Second,
					PublishDelay:    5 * time.Minute,
				},
				Server: wantDefaultServer,
				State: StateConfig{
					Driver:   StateDriverSQLite,
					Postgres: wantDefaultPostgres,
					Sqlite: SqliteConfig{
						Path:        "/var/lib/tempogate/state.db",
						MaxConns:    1,
						BusyTimeout: 5 * time.Second,
					},
					ReaperInterval: 5 * time.Minute,
				},
				OIDC: OIDCConfig{
					Issuer:              "https://tempogate.internal.example.com",
					SessionTTL:          5 * time.Minute,
					AccessTokenTTL:      4 * time.Hour,
					AccessTokenAudience: "temporal",
					RefreshTokenTTL:     7 * 24 * time.Hour,
					RefreshMaxLifetime:  7 * 24 * time.Hour,
					Google: GoogleConfig{
						AuthEndpoint:  "https://accounts.google.com/o/oauth2/v2/auth",
						TokenEndpoint: "https://oauth2.googleapis.com/token",
						IssuerURL:     "https://accounts.google.com",
					},
				},
			},
		},
		{
			name: "oidc clients and google overridden by env",
			env: map[string]string{
				"OIDC_CLIENTS":              "ui:https://temporal.example.com/auth/sso/callback,cli:http://127.0.0.1/callback",
				"OIDC_GOOGLE_CLIENT_ID":     "google-client-123.apps.googleusercontent.com",
				"OIDC_GOOGLE_AUTH_ENDPOINT": "http://127.0.0.1:9999/mock/auth",
			},
			want: &Config{
				Log: LogConfig{Level: "info", Format: log.FormatAuto, Requests: true},
				HTTP: HTTPConfig{
					Listener: Listener{
						IP:   net.IPv4(127, 0, 0, 1),
						Port: 8000,
					},
					RateLimit: defaultRateLimits,
				},
				Admin: AdminConfig{
					Listener: Listener{
						IP:   net.IPv4(127, 0, 0, 1),
						Port: 8081,
					},
					Keys: AdminKeysConfig{MaxTTL: 90 * 24 * time.Hour},
				},
				Keys: KeysConfig{
					RetirementGrace: 4 * time.Hour,
					ReloadInterval:  30 * time.Second,
					PublishDelay:    5 * time.Minute,
				},
				Server: wantDefaultServer,
				State: StateConfig{
					Driver:   StateDriverSQLite,
					Postgres: wantDefaultPostgres,
					Sqlite: SqliteConfig{
						Path:        "/var/lib/tempogate/state.db",
						MaxConns:    1,
						BusyTimeout: 5 * time.Second,
					},
					ReaperInterval: 5 * time.Minute,
				},
				OIDC: OIDCConfig{
					Issuer:              "http://127.0.0.1:8000",
					Clients:             "ui:https://temporal.example.com/auth/sso/callback,cli:http://127.0.0.1/callback",
					SessionTTL:          5 * time.Minute,
					AccessTokenTTL:      4 * time.Hour,
					AccessTokenAudience: "temporal",
					RefreshTokenTTL:     7 * 24 * time.Hour,
					RefreshMaxLifetime:  7 * 24 * time.Hour,
					Google: GoogleConfig{
						ClientID:      "google-client-123.apps.googleusercontent.com",
						AuthEndpoint:  "http://127.0.0.1:9999/mock/auth",
						TokenEndpoint: "https://oauth2.googleapis.com/token",
						IssuerURL:     "https://accounts.google.com",
					},
				},
			},
		},
		{
			name: "insecure redirect URIs opt-in overridden by env",
			env: map[string]string{
				"OIDC_ALLOW_INSECURE_REDIRECT_URIS": "true",
			},
			want: &Config{
				Log: LogConfig{Level: "info", Format: log.FormatAuto, Requests: true},
				HTTP: HTTPConfig{
					Listener: Listener{
						IP:   net.IPv4(127, 0, 0, 1),
						Port: 8000,
					},
					RateLimit: defaultRateLimits,
				},
				Admin: AdminConfig{
					Listener: Listener{
						IP:   net.IPv4(127, 0, 0, 1),
						Port: 8081,
					},
					Keys: AdminKeysConfig{MaxTTL: 90 * 24 * time.Hour},
				},
				Keys: KeysConfig{
					RetirementGrace: 4 * time.Hour,
					ReloadInterval:  30 * time.Second,
					PublishDelay:    5 * time.Minute,
				},
				Server: wantDefaultServer,
				State: StateConfig{
					Driver:   StateDriverSQLite,
					Postgres: wantDefaultPostgres,
					Sqlite: SqliteConfig{
						Path:        "/var/lib/tempogate/state.db",
						MaxConns:    1,
						BusyTimeout: 5 * time.Second,
					},
					ReaperInterval: 5 * time.Minute,
				},
				OIDC: OIDCConfig{
					Issuer:                    "http://127.0.0.1:8000",
					AllowInsecureRedirectURIs: true,
					SessionTTL:                5 * time.Minute,
					AccessTokenTTL:            4 * time.Hour,
					AccessTokenAudience:       "temporal",
					RefreshTokenTTL:           7 * 24 * time.Hour,
					RefreshMaxLifetime:        7 * 24 * time.Hour,
					Google: GoogleConfig{
						AuthEndpoint:  "https://accounts.google.com/o/oauth2/v2/auth",
						TokenEndpoint: "https://oauth2.googleapis.com/token",
						IssuerURL:     "https://accounts.google.com",
					},
				},
			},
		},
		{
			name: "callback allowlist and google credentials overridden by env",
			env: map[string]string{
				"OIDC_ALLOWED_DOMAINS":        "example.com,corp.example.org",
				"OIDC_ALLOWED_HOSTED_DOMAINS": "example.com",
				"OIDC_GOOGLE_CLIENT_SECRET":   "gocspx-secret",
				"OIDC_GOOGLE_TOKEN_ENDPOINT":  "http://127.0.0.1:9999/mock/token",
				"OIDC_GOOGLE_ISSUER_URL":      "http://127.0.0.1:9999",
			},
			want: &Config{
				Log: LogConfig{Level: "info", Format: log.FormatAuto, Requests: true},
				HTTP: HTTPConfig{
					Listener: Listener{
						IP:   net.IPv4(127, 0, 0, 1),
						Port: 8000,
					},
					RateLimit: defaultRateLimits,
				},
				Admin: AdminConfig{
					Listener: Listener{
						IP:   net.IPv4(127, 0, 0, 1),
						Port: 8081,
					},
					Keys: AdminKeysConfig{MaxTTL: 90 * 24 * time.Hour},
				},
				Keys: KeysConfig{
					RetirementGrace: 4 * time.Hour,
					ReloadInterval:  30 * time.Second,
					PublishDelay:    5 * time.Minute,
				},
				Server: wantDefaultServer,
				State: StateConfig{
					Driver:   StateDriverSQLite,
					Postgres: wantDefaultPostgres,
					Sqlite: SqliteConfig{
						Path:        "/var/lib/tempogate/state.db",
						MaxConns:    1,
						BusyTimeout: 5 * time.Second,
					},
					ReaperInterval: 5 * time.Minute,
				},
				OIDC: OIDCConfig{
					Issuer:               "http://127.0.0.1:8000",
					AllowedDomains:       "example.com,corp.example.org",
					AllowedHostedDomains: "example.com",
					SessionTTL:           5 * time.Minute,
					AccessTokenTTL:       4 * time.Hour,
					AccessTokenAudience:  "temporal",
					RefreshTokenTTL:      7 * 24 * time.Hour,
					RefreshMaxLifetime:   7 * 24 * time.Hour,
					Google: GoogleConfig{
						ClientSecret:  "gocspx-secret",
						AuthEndpoint:  "https://accounts.google.com/o/oauth2/v2/auth",
						TokenEndpoint: "http://127.0.0.1:9999/mock/token",
						IssuerURL:     "http://127.0.0.1:9999",
					},
				},
			},
		},
		{
			name: "session ttl and signing key overridden by env",
			env: map[string]string{
				"OIDC_SESSION_TTL":         "10m",
				"OIDC_SESSION_SIGNING_KEY": "ZXhhbXBsZS1zaWduaW5nLWtleS1mb3ItdGVzdGluZw",
			},
			want: &Config{
				Log: LogConfig{Level: "info", Format: log.FormatAuto, Requests: true},
				HTTP: HTTPConfig{
					Listener: Listener{
						IP:   net.IPv4(127, 0, 0, 1),
						Port: 8000,
					},
					RateLimit: defaultRateLimits,
				},
				Admin: AdminConfig{
					Listener: Listener{
						IP:   net.IPv4(127, 0, 0, 1),
						Port: 8081,
					},
					Keys: AdminKeysConfig{MaxTTL: 90 * 24 * time.Hour},
				},
				Keys: KeysConfig{
					RetirementGrace: 4 * time.Hour,
					ReloadInterval:  30 * time.Second,
					PublishDelay:    5 * time.Minute,
				},
				Server: wantDefaultServer,
				State: StateConfig{
					Driver:   StateDriverSQLite,
					Postgres: wantDefaultPostgres,
					Sqlite: SqliteConfig{
						Path:        "/var/lib/tempogate/state.db",
						MaxConns:    1,
						BusyTimeout: 5 * time.Second,
					},
					ReaperInterval: 5 * time.Minute,
				},
				OIDC: OIDCConfig{
					Issuer:              "http://127.0.0.1:8000",
					SessionTTL:          10 * time.Minute,
					AccessTokenTTL:      4 * time.Hour,
					AccessTokenAudience: "temporal",
					RefreshTokenTTL:     7 * 24 * time.Hour,
					RefreshMaxLifetime:  7 * 24 * time.Hour,
					SessionSigningKey:   "ZXhhbXBsZS1zaWduaW5nLWtleS1mb3ItdGVzdGluZw",
					Google: GoogleConfig{
						AuthEndpoint:  "https://accounts.google.com/o/oauth2/v2/auth",
						TokenEndpoint: "https://oauth2.googleapis.com/token",
						IssuerURL:     "https://accounts.google.com",
					},
				},
			},
		},
		{
			name: "api docs opted in by env",
			env:  map[string]string{"API_DOCS_ENABLED": "true"},
			want: func() *Config {
				c := defaultConfig()
				c.API.DocsEnabled = true
				return c
			}(),
		},
		{
			name: "insecure issuer opt-in overridden by env",
			env: map[string]string{
				"OIDC_ISSUER":                "http://tempogate:8000",
				"OIDC_ALLOW_INSECURE_ISSUER": "true",
			},
			want: func() *Config {
				c := defaultConfig()
				c.OIDC.Issuer = "http://tempogate:8000"
				c.OIDC.AllowInsecureIssuer = true
				return c
			}(),
		},
		{
			name: "server timeouts and limits overridden by env",
			env: map[string]string{
				"SERVER_READ_HEADER_TIMEOUT": "1s",
				"SERVER_READ_TIMEOUT":        "2s",
				"SERVER_WRITE_TIMEOUT":       "3s",
				"SERVER_IDLE_TIMEOUT":        "4s",
				"SERVER_MAX_HEADER_BYTES":    "8192",
				"SERVER_SHUTDOWN_TIMEOUT":    "5s",
			},
			want: func() *Config {
				c := defaultConfig()
				c.Server = ServerConfig{
					ReadHeaderTimeout: 1 * time.Second,
					ReadTimeout:       2 * time.Second,
					WriteTimeout:      3 * time.Second,
					IdleTimeout:       4 * time.Second,
					MaxHeaderBytes:    8192,
					ShutdownTimeout:   5 * time.Second,
				}
				return c
			}(),
		},
	}

	for _, tc := range cases {
		s.Run(tc.name, func() {
			for k, v := range tc.env {
				s.T().Setenv(k, v)
			}

			got, err := New(Params{})
			s.Require().NoError(err)
			s.Equal(tc.want, got.Config)
		})
	}
}

// TestRejectsInvalidLogConfig: a typo in LOG_LEVEL or LOG_FORMAT fails the
// load with a message naming the valid values, rather than silently picking
// one.
func (s *ConfigSuite) TestRejectsInvalidLogConfig() {
	for env, want := range map[string]string{
		"LOG_FORMAT": `invalid config: LOG_FORMAT must be "auto", "json" or "pretty", got "console"`,
		"LOG_LEVEL":  `invalid config: LOG_LEVEL must be "debug", "info", "warn" or "error", got "console"`,
	} {
		s.Run(env, func() {
			s.T().Setenv(env, "console")
			_, err := New(Params{})
			s.Require().EqualError(err, want)
		})
	}
}

// TestNormalizesLogConfig: the level and format are read as zap reads
// LOG_LEVEL, ignoring case and surrounding space, and empty is the default.
func (s *ConfigSuite) TestNormalizesLogConfig() {
	for _, tc := range []struct {
		level, format string
		want          LogConfig
	}{
		{"", "", LogConfig{Level: "info", Format: log.FormatAuto, Requests: true}},
		{" DEBUG ", "JSON", LogConfig{Level: "debug", Format: log.FormatJSON, Requests: true}},
		{"Warn", " Pretty\t", LogConfig{Level: "warn", Format: log.FormatPretty, Requests: true}},
	} {
		s.Run(tc.level+"/"+tc.format, func() {
			s.T().Setenv("LOG_LEVEL", tc.level)
			s.T().Setenv("LOG_FORMAT", tc.format)
			got, err := New(Params{})
			s.Require().NoError(err)
			s.Equal(tc.want, got.Config.Log)
		})
	}
}

func (s *ConfigSuite) TestKeysEncryptionKeyFromEnv() {
	s.T().Setenv("KEYS_ENCRYPTION_KEY", "a2V5")
	s.T().Setenv("KEYS_ENCRYPTION_KEY_FILE", "/run/secrets/kek")

	got, err := New(Params{})
	s.Require().NoError(err)
	s.Equal("a2V5", got.Config.Keys.EncryptionKey)
	s.Equal("/run/secrets/kek", got.Config.Keys.EncryptionKeyFile)
}

func (s *ConfigSuite) TestFxProjectsKeysEncryptionKey() {
	s.T().Setenv("KEYS_ENCRYPTION_KEY", "a2V5")
	s.T().Setenv("KEYS_ENCRYPTION_KEY_FILE", "/run/secrets/kek")

	var got struct {
		fx.In
		Key  string `name:"keys_encryption_key"`
		File string `name:"keys_encryption_key_file"`
	}
	app := fx.New(fx.NopLogger, Fx(), fx.Populate(&got))
	s.Require().NoError(app.Err())
	s.Equal("a2V5", got.Key)
	s.Equal("/run/secrets/kek", got.File)
}

func (s *ConfigSuite) TestAbuseControlsFromEnv() {
	s.T().Setenv("HTTP_TRUSTED_PROXIES", "10.0.0.0/8,192.0.2.7")
	s.T().Setenv("HTTP_RATE_LIMIT_AUTHORIZE", "100")
	s.T().Setenv("HTTP_RATE_LIMIT_DEVICE_AUTHORIZATION", "0")
	s.T().Setenv("HTTP_RATE_LIMIT_DEVICE_VERIFICATION", "7")
	s.T().Setenv("HTTP_RATE_LIMIT_TOKEN", "600")
	s.T().Setenv("STATE_REAPER_INTERVAL", "30s")

	var got struct {
		fx.In
		TrustedProxies string        `name:"http_trusted_proxies"`
		Authorize      int           `name:"http_rate_limit_authorize"`
		DeviceAuthz    int           `name:"http_rate_limit_device_authorization"`
		DeviceVerify   int           `name:"http_rate_limit_device_verification"`
		Token          int           `name:"http_rate_limit_token"`
		ReaperInterval time.Duration `name:"state_reaper_interval"`
	}
	app := fx.New(fx.NopLogger, Fx(), fx.Populate(&got))
	s.Require().NoError(app.Err())
	s.Equal("10.0.0.0/8,192.0.2.7", got.TrustedProxies)
	s.Equal(100, got.Authorize)
	s.Zero(got.DeviceAuthz, "0 disables one endpoint's limit")
	s.Equal(7, got.DeviceVerify)
	s.Equal(600, got.Token)
	s.Equal(30*time.Second, got.ReaperInterval)
}
