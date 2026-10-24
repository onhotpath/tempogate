package sqlite

import (
	"context"
	"errors"
	"time"

	"github.com/onhotpath/tempogate/keys"
)

// DumpTables reports every table but schema_migrations, with the columns
// in table order and the values as the driver scans them.
func (s *StoreSuite) TestDumpTables() {
	created := time.Date(2001, 2, 3, 4, 5, 6, 123456000, time.UTC)
	s.Require().NoError(s.store.SaveKeypair(s.ctx, keys.Keypair{
		Kid: "kid-1", Alg: "RS256", PrivatePEM: []byte("priv"), PublicPEM: []byte("pub"), CreatedAt: created,
	}))

	var tables []string
	err := s.store.DumpTables(s.ctx, func(table string, columns []string, rows [][]any) error {
		tables = append(tables, table)
		if table != "keypairs" {
			return nil
		}
		s.Equal([]string{"kid", "alg", "private_pem", "public_pem", "created_at", "retired_at"}, columns)
		s.Require().Len(rows, 1)
		s.Equal("kid-1", rows[0][0])
		s.Equal([]byte("priv"), rows[0][2])
		got, ok := rows[0][4].(time.Time)
		s.Require().Truef(ok, "created_at scans as time.Time, got %T", rows[0][4])
		s.True(created.Equal(got))
		s.Nil(rows[0][5])
		return nil
	})
	s.Require().NoError(err)
	s.Equal([]string{
		"auth_codes", "auth_requests", "browser_sessions", "device_codes",
		"integration_keys", "jti_denylist", "keypairs", "refresh_tokens",
	}, tables)
}

func (s *StoreSuite) TestDumpTablesStopsAtAVisitError() {
	stop := errors.New("stop")
	calls := 0
	err := s.store.DumpTables(s.ctx, func(string, []string, [][]any) error {
		calls++
		return stop
	})
	s.Require().ErrorIs(err, stop)
	s.Equal(1, calls)
}

func (s *StoreSuite) TestDumpTablesAfterClose() {
	s.Require().NoError(s.store.Close())
	s.Require().Error(s.store.DumpTables(s.ctx, func(string, []string, [][]any) error { return nil }))
	s.store = nil
}

// A table that cannot be read fails the dump, naming the table.
func (s *StoreSuite) TestDumpTablesFailsOnAnUnreadableTable() {
	ctx, cancel := context.WithCancel(s.ctx)
	defer cancel()
	err := s.store.DumpTables(ctx, func(string, []string, [][]any) error {
		cancel()
		return nil
	})
	s.Require().ErrorIs(err, context.Canceled)
	s.Require().ErrorContains(err, "sqlite: read auth_requests")
}
