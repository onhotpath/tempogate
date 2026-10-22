package postgres

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestNewRefusesAnInsecureRemoteDSN(t *testing.T) {
	cases := []struct {
		name, dsn string
		ok        bool
	}{
		{"verify-full", "postgres://u:p@db.example.com/x?sslmode=verify-full", true},
		{"verify-full, keyword form", "host=db.example.com dbname=x sslmode=verify-full", true},
		{"verify-full, several hosts", "postgres://u:p@db1.example.com,db2.example.com/x?sslmode=verify-full", true},
		{"loopback without TLS", "postgres://u:p@127.0.0.1:5432/x?sslmode=disable", true},
		{"localhost without TLS", "postgres://u:p@localhost/x?sslmode=disable", true},
		{"IPv6 loopback without TLS", "postgres://u:p@[::1]/x?sslmode=disable", true},
		{"unix socket", "host=/var/run/postgresql dbname=x", true},
		{"default sslmode (prefer)", "postgres://u:p@db.example.com/x", false},
		{"disable", "postgres://u:p@db.example.com/x?sslmode=disable", false},
		{"require", "postgres://u:p@db.example.com/x?sslmode=require", false},
		{"verify-ca", "postgres://u:p@db.example.com/x?sslmode=verify-ca", false},
		{"one insecure host among several", "postgres://u:p@localhost,db.example.com/x?sslmode=disable", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := New(WithDSN(tc.dsn))
			if tc.ok {
				require.NoError(t, err)
				require.NoError(t, s.Close())
				return
			}
			require.ErrorContains(t, err, `postgres: STATE_POSTGRES_DSN host "db.example.com" must use sslmode=verify-full`)
			require.ErrorContains(t, err, "STATE_POSTGRES_ALLOW_INSECURE_SSLMODE=true")
			require.NotContains(t, err.Error(), ":p@", "the DSN, password included, is never echoed")
		})
	}
}

func TestAllowInsecureSSLModeWarnsOnce(t *testing.T) {
	core, logs := observer.New(zapcore.WarnLevel)
	s, err := New(
		WithDSN("postgres://u:p@db.example.com/x?sslmode=require"),
		WithListenDSN("postgres://u:p@direct.example.com/x?sslmode=disable"),
		WithAllowInsecureSSLMode(true),
		WithLogger(zap.New(core)),
	)
	require.NoError(t, err)
	require.NoError(t, s.Close())

	warned := logs.FilterMessageSnippet("STATE_POSTGRES_ALLOW_INSECURE_SSLMODE").All()
	require.Len(t, warned, 2)
	require.Equal(t, "db.example.com", warned[0].ContextMap()["host"])
	require.Equal(t, "STATE_POSTGRES_LISTEN_DSN", warned[1].ContextMap()["setting"])
}

func TestNewValidatesItsSettings(t *testing.T) {
	file := filepath.Join(t.TempDir(), "dsn")
	require.NoError(t, os.WriteFile(file, []byte("postgres://localhost/x\n"), 0o600))

	cases := []struct {
		name string
		opts []Option
		err  string
	}{
		{"no DSN", nil, "postgres: set exactly one of STATE_POSTGRES_DSN and STATE_POSTGRES_DSN_FILE"},
		{"both DSNs", []Option{WithDSN("postgres://localhost/x"), WithDSNFile(file)}, "set exactly one of"},
		{"one connection", []Option{WithDSN("postgres://localhost/x"), WithMaxConns(1)}, "STATE_POSTGRES_MAX_CONNS must be at least 2, got 1"},
		{"negative idle time", []Option{WithDSN("postgres://localhost/x"), WithConnMaxIdleTime(-time.Second)}, "STATE_POSTGRES_CONN_MAX_IDLE_TIME must not be negative"},
		{"unparsable DSN", []Option{WithDSN("postgres://u:secretpw@localhost:notaport/x")}, "postgres: parse STATE_POSTGRES_DSN: "},
		{"missing DSN file", []Option{WithDSNFile(filepath.Join(t.TempDir(), "absent"))}, "postgres: read STATE_POSTGRES_DSN_FILE: "},
		{"insecure listen DSN", []Option{WithDSN("postgres://localhost/x"), WithListenDSN("postgres://direct.example.com/x")}, `STATE_POSTGRES_LISTEN_DSN host "direct.example.com"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.opts...)
			require.ErrorContains(t, err, tc.err)
			require.NotContains(t, err.Error(), "secretpw")
		})
	}

	s, err := New(WithDSNFile(file))
	require.NoError(t, err, "a DSN file is trimmed")
	require.NoError(t, s.Close())
}

// TestDSNFileIsReadForEveryNewConnection: a rotated Secret takes effect on
// the next connection the pool opens, without a restart.
func TestDSNFileIsReadForEveryNewConnection(t *testing.T) {
	forEachServer(t, func(t *testing.T, srv testServer) {
		first, second := newDatabase(t, srv), newDatabase(t, srv)
		file := filepath.Join(t.TempDir(), "dsn")
		require.NoError(t, os.WriteFile(file, []byte(first), 0o600))

		s, err := New(WithDSNFile(file))
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, s.Close()) })
		require.NoError(t, s.Migrate(t.Context()))
		require.NoError(t, s.IsCurrent(t.Context()))

		require.NoError(t, os.WriteFile(file, []byte(second), 0o600))
		s.pool.Reset()
		require.ErrorContains(t, s.IsCurrent(t.Context()), "schema version 0", "new connections use the rewritten DSN")

		require.NoError(t, os.WriteFile(file, []byte("postgres://u:p@db.example.com/x?sslmode=require"), 0o600))
		s.pool.Reset()
		require.ErrorContains(t, s.Ping(t.Context()), "must use sslmode=verify-full", "the TLS policy holds for a rewritten DSN too")
	})
}
