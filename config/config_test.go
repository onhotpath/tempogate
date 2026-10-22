package config

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"go.uber.org/fx"
)

type ConfigSuite struct {
	suite.Suite
}

var defaultRateLimits = RateLimitConfig{Authorize: 30, DeviceAuthorization: 10, DeviceVerification: 20, Token: 60}

func TestConfigSuite(t *testing.T) {
	suite.Run(t, new(ConfigSuite))
}

func (s *ConfigSuite) TestNew() {
	cases := []struct {
		name string
		env  map[string]string
		want *Config
	}{
		{
			name: "defaults",
			want: &Config{
				Log: LogConfig{Level: "info"},
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
				},
				State: StateConfig{
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
					RefreshMaxLifetime:  30 * 24 * time.Hour,
					Google: GoogleConfig{
						AuthEndpoint:  "https://accounts.google.com/o/oauth2/v2/auth",
						TokenEndpoint: "https://oauth2.googleapis.com/token",
						IssuerURL:     "https://accounts.google.com",
					},
				},
			},
		},
		{
			name: "log and http overridden by env",
			env: map[string]string{
				"LOG_LEVEL":     "debug",
				"HTTP_LISTENER": "0.0.0.0:9000",
			},
			want: &Config{
				Log: LogConfig{Level: "debug"},
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
				},
				State: StateConfig{
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
					RefreshMaxLifetime:  30 * 24 * time.Hour,
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
				"OIDC_REFRESH_MAX_LIFETIME":  "168h",
			},
			want: &Config{
				Log: LogConfig{Level: "info"},
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
				},
				State: StateConfig{
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
			name: "admin listener overridden by env",
			env: map[string]string{
				"ADMIN_LISTENER": "127.0.0.1:9091",
			},
			want: &Config{
				Log: LogConfig{Level: "info"},
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
				},
				State: StateConfig{
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
					RefreshMaxLifetime:  30 * 24 * time.Hour,
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
				Log: LogConfig{Level: "info"},
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
				},
				State: StateConfig{
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
					RefreshMaxLifetime:  30 * 24 * time.Hour,
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
				Log: LogConfig{Level: "info"},
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
				},
				State: StateConfig{
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
					RefreshMaxLifetime:  30 * 24 * time.Hour,
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
				Log: LogConfig{Level: "info"},
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
				},
				State: StateConfig{
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
					RefreshMaxLifetime:  30 * 24 * time.Hour,
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
				Log: LogConfig{Level: "info"},
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
				},
				State: StateConfig{
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
					RefreshMaxLifetime:        30 * 24 * time.Hour,
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
				"OIDC_ALLOWED_DOMAINS":       "example.com,corp.example.org",
				"OIDC_GOOGLE_CLIENT_SECRET":  "gocspx-secret",
				"OIDC_GOOGLE_TOKEN_ENDPOINT": "http://127.0.0.1:9999/mock/token",
				"OIDC_GOOGLE_ISSUER_URL":     "http://127.0.0.1:9999",
			},
			want: &Config{
				Log: LogConfig{Level: "info"},
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
				},
				State: StateConfig{
					Sqlite: SqliteConfig{
						Path:        "/var/lib/tempogate/state.db",
						MaxConns:    1,
						BusyTimeout: 5 * time.Second,
					},
					ReaperInterval: 5 * time.Minute,
				},
				OIDC: OIDCConfig{
					Issuer:              "http://127.0.0.1:8000",
					AllowedDomains:      "example.com,corp.example.org",
					SessionTTL:          5 * time.Minute,
					AccessTokenTTL:      4 * time.Hour,
					AccessTokenAudience: "temporal",
					RefreshTokenTTL:     7 * 24 * time.Hour,
					RefreshMaxLifetime:  30 * 24 * time.Hour,
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
				Log: LogConfig{Level: "info"},
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
				},
				State: StateConfig{
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
					RefreshMaxLifetime:  30 * 24 * time.Hour,
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
	}

	for _, tc := range cases {
		s.Run(tc.name, func() {
			for k, v := range tc.env {
				s.T().Setenv(k, v)
			}

			got, err := New(Params{})
			s.Require().NoError(err)
			s.Equal(tc.want, got)
		})
	}
}

func (s *ConfigSuite) TestKeysEncryptionKeyFromEnv() {
	s.T().Setenv("KEYS_ENCRYPTION_KEY", "a2V5")
	s.T().Setenv("KEYS_ENCRYPTION_KEY_FILE", "/run/secrets/kek")

	got, err := New(Params{})
	s.Require().NoError(err)
	s.Equal(KeysConfig{EncryptionKey: "a2V5", EncryptionKeyFile: "/run/secrets/kek"}, got.Keys)
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
