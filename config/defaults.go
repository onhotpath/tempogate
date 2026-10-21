package config

import (
	"net"
	"time"
)

func defaultConfig() *Config {
	return &Config{
		Log: LogConfig{Level: "info"},
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
			Issuer:             "http://127.0.0.1:8000",
			SessionTTL:         5 * time.Minute,
			AccessTokenTTL:     4 * time.Hour,
			RefreshTokenTTL:    7 * 24 * time.Hour,
			RefreshMaxLifetime: 30 * 24 * time.Hour,
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
