package postgres

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/onhotpath/tempogate/redact"
)

// connSource is where a connection string comes from: inline, or a file
// read again for every new connection. setting names it in errors.
type connSource struct {
	dsn           string
	file          string
	setting       string
	allowInsecure bool
	logger        *zap.Logger
	// redaction learns the password of every DSN read, so a rotated one is
	// masked too.
	redaction *redact.Set
}

func (c connSource) read() (string, error) {
	if c.file == "" {
		return c.dsn, nil
	}
	b, err := os.ReadFile(c.file) // #nosec G304 -- operator-configured STATE_POSTGRES_DSN_FILE.
	if err != nil {
		return "", fmt.Errorf("postgres: read %s: %w", c.setting, err)
	}
	return strings.TrimSpace(string(b)), nil
}

// poolConfig parses the DSN, pool_* parameters included, and applies the
// TLS policy.
func (c connSource) poolConfig() (*pgxpool.Config, error) {
	dsn, err := c.read()
	if err != nil {
		return nil, err
	}
	// pgx redacts the password from parse errors.
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres: parse %s: %w", c.setting, err)
	}
	c.redaction.Declare(redact.Secret, cfg.ConnConfig.Password)
	if err := c.checkTLS(&cfg.ConnConfig.Config); err != nil {
		return nil, err
	}
	return cfg, nil
}

// connConfig is poolConfig for a single connection (the LISTEN one).
func (c connSource) connConfig() (*pgx.ConnConfig, error) {
	cfg, err := c.poolConfig()
	if err != nil {
		return nil, err
	}
	return cfg.ConnConfig, nil
}

// beforeConnect re-reads a DSN file for each new pooled connection, so a
// rotated password (or a whole new DSN) applies without a restart. Pool
// settings (pool_max_conns and the STATE_POSTGRES_* limits) stay as read at
// startup.
func (c connSource) beforeConnect(_ context.Context, cc *pgx.ConnConfig) error {
	c.logger = zap.NewNop() // New already warned about an allowed insecure sslmode
	fresh, err := c.poolConfig()
	if err != nil {
		return err
	}
	cc.Config = fresh.ConnConfig.Config
	return nil
}

// checkTLS refuses a connection that could reach a remote server without
// authenticating it: every host pgx may try, fallbacks included, must use
// TLS with certificate and host name verification (sslmode=verify-full),
// unless it is a Unix socket or a loopback address. require and verify-ca
// encrypt but accept any server (or any server of the CA), and prefer and
// allow fall back to plain text, so a man in the middle can read every
// token and signing key the store holds. allowInsecure (development only)
// downgrades the refusal to a warning.
func (c connSource) checkTLS(cfg *pgconn.Config) error {
	attempts := append([]*pgconn.FallbackConfig{{Host: cfg.Host, Port: cfg.Port, TLSConfig: cfg.TLSConfig}}, cfg.Fallbacks...)
	for _, a := range attempts {
		if isLocalHost(a.Host) || (a.TLSConfig != nil && !a.TLSConfig.InsecureSkipVerify) {
			continue
		}
		if c.allowInsecure {
			c.logger.Warn("Postgres connection without sslmode=verify-full allowed by STATE_POSTGRES_ALLOW_INSECURE_SSLMODE; do not use in production",
				zap.String("setting", c.setting), zap.String("host", a.Host))
			continue
		}
		return fmt.Errorf("postgres: %s host %q must use sslmode=verify-full (weaker modes do not authenticate the server; "+
			"only Unix sockets, localhost, 127.0.0.0/8 and ::1 are exempt); "+
			"set STATE_POSTGRES_ALLOW_INSECURE_SSLMODE=true to allow it for development", c.setting, a.Host)
	}
	return nil
}

// isLocalHost reports a Unix socket directory or a loopback host, whose
// traffic never leaves the machine.
func isLocalHost(host string) bool {
	if strings.HasPrefix(host, "/") || strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
