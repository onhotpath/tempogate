package config

import (
	"net"
	"time"
)

func defaultConfig() *Config {
	return &Config{
		Log: LogConfig{Level: "info", Requests: true},
		HTTP: HTTPConfig{
			Listener: Listener{
				IP:   net.IPv4(127, 0, 0, 1),
				Port: 8000,
			},
			RateLimit: RateLimitConfig{
				Authorize:           30,
				DeviceAuthorization: 10,
				DeviceVerification:  20,
				Token:               60,
			},
		},
		Admin: AdminConfig{
			Listener: Listener{
				IP:   net.IPv4(127, 0, 0, 1),
				Port: 8081,
			},
			Keys: AdminKeysConfig{MaxTTL: 90 * 24 * time.Hour},
		},
		Keys: KeysConfig{
			// Matches the human access-token TTL.
			RetirementGrace: 4 * time.Hour,
			ReloadInterval:  30 * time.Second,
			// Covers Temporal's default 1m JWKS refresh with margin.
			PublishDelay: 5 * time.Minute,
		},
		// WriteTimeout covers the whole handler, so it must outlast the
		// slowest legitimate one: the Google callback's outbound code
		// exchange + JWKS fetch. No handler streams or long-polls.
		Server: ServerConfig{
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    16 << 10,
			ShutdownTimeout:   15 * time.Second,
		},
		State: StateConfig{
			Driver: StateDriverSQLite,
			Postgres: PostgresConfig{
				MaxConns:        10,
				ConnMaxIdleTime: 30 * time.Minute,
			},
			Sqlite: SqliteConfig{
				Path:        "/var/lib/tempogate/state.db",
				MaxConns:    1,
				BusyTimeout: 5 * time.Second,
			},
			ReaperInterval: 5 * time.Minute,
		},
		OIDC: OIDCConfig{
			Issuer:         "http://127.0.0.1:8000",
			SessionTTL:     5 * time.Minute,
			AccessTokenTTL: 4 * time.Hour,
			// Any value works with a Temporal frontend that checks no
			// audience (every release before v1.29.0, and later ones unless
			// configured), so the default changes nothing for existing setups.
			AccessTokenAudience: "temporal",
			RefreshTokenTTL:     7 * 24 * time.Hour,
			RefreshMaxLifetime:  7 * 24 * time.Hour,
			Google: GoogleConfig{
				AuthEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
				// #nosec G101 -- public Google token endpoint URL, not a
				// credential; G101 trips on the "Token" in the field name.
				TokenEndpoint: "https://oauth2.googleapis.com/token",
				IssuerURL:     "https://accounts.google.com",
			},
		},
	}
}
