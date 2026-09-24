package config

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

type ConfigSuite struct {
	suite.Suite
}

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
				},
				OIDC: OIDCConfig{
					Issuer:     "http://127.0.0.1:8000",
					SessionTTL: 5 * time.Minute,
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
				},
				OIDC: OIDCConfig{
					Issuer:     "http://127.0.0.1:8000",
					SessionTTL: 5 * time.Minute,
					Google: GoogleConfig{
						AuthEndpoint:  "https://accounts.google.com/o/oauth2/v2/auth",
						TokenEndpoint: "https://oauth2.googleapis.com/token",
						IssuerURL:     "https://accounts.google.com",
					},
				},
			},
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
				},
				OIDC: OIDCConfig{
					Issuer:     "http://127.0.0.1:8000",
					SessionTTL: 5 * time.Minute,
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
				},
				OIDC: OIDCConfig{
					Issuer:     "http://127.0.0.1:8000",
					SessionTTL: 5 * time.Minute,
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
				},
				OIDC: OIDCConfig{
					Issuer:     "https://tempogate.internal.example.com",
					SessionTTL: 5 * time.Minute,
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
				"OIDC_CLIENTS":              "ui:https://temporal.example.com/auth/sso/callback,cli:http://127.0.0.1",
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
				},
				OIDC: OIDCConfig{
					Issuer:     "http://127.0.0.1:8000",
					Clients:    "ui:https://temporal.example.com/auth/sso/callback,cli:http://127.0.0.1",
					SessionTTL: 5 * time.Minute,
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
				},
				OIDC: OIDCConfig{
					Issuer:         "http://127.0.0.1:8000",
					AllowedDomains: "example.com,corp.example.org",
					SessionTTL:     5 * time.Minute,
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
				},
				OIDC: OIDCConfig{
					Issuer:            "http://127.0.0.1:8000",
					SessionTTL:        10 * time.Minute,
					SessionSigningKey: "ZXhhbXBsZS1zaWduaW5nLWtleS1mb3ItdGVzdGluZw",
					Google: GoogleConfig{
						AuthEndpoint:  "https://accounts.google.com/o/oauth2/v2/auth",
						TokenEndpoint: "https://oauth2.googleapis.com/token",
						IssuerURL:     "https://accounts.google.com",
					},
				},
			},
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
