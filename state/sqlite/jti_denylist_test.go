package sqlite

import (
	"path/filepath"
	"time"

	"github.com/onhotpath/tempogate/admin"
)

// denylistSeedOpts is the minimal valid IntegrationKey shape — non-empty
// namespace/owner and a role that satisfies the CHECK on integration_keys.
// Each test that needs a row supplies these so the row passes validation
// without re-stating the option list.
func denylistSeedOpts() []admin.Option {
	return []admin.Option{
		admin.WithNamespace("ns"),
		admin.WithRole(admin.RoleRead),
		admin.WithOwner("o"),
	}
}

// jti_denylist_test.go extends StoreSuite (defined in store_test.go) with the
// keys.DenylistChecker contract and the dual-write guarantee tied to
// MarkIntegrationKeyRevoked. The denylist row must persist across a Close +
// re-open of the same .db file — the backing data lives in SQLite, not in
// the in-process verifier cache.

func (s *StoreSuite) TestIsRevokedUnknownJTI() {
	got, err := s.store.IsRevoked(s.ctx, "never-revoked")
	s.Require().NoError(err)
	s.False(got)
}

func (s *StoreSuite) TestMarkIntegrationKeyRevokedAlsoHydratesDenylist() {
	k := s.seedKey(denylistSeedOpts()...)
	_, err := s.store.MarkIntegrationKeyRevoked(s.ctx, k.ID)
	s.Require().NoError(err)

	got, err := s.store.IsRevoked(s.ctx, k.JTI)
	s.Require().NoError(err)
	s.True(got, "MarkIntegrationKeyRevoked must write the jti to jti_denylist in the same transaction")
}

func (s *StoreSuite) TestDenylistEntryIsIdempotentAcrossRepeatRevokes() {
	k := s.seedKey(denylistSeedOpts()...)
	// First revoke writes both rows.
	_, err := s.store.MarkIntegrationKeyRevoked(s.ctx, k.ID)
	s.Require().NoError(err)

	var rowsBefore int
	s.Require().NoError(s.store.db.QueryRowContext(s.ctx,
		`SELECT count(*) FROM jti_denylist WHERE jti = ?`, k.JTI,
	).Scan(&rowsBefore))
	s.Equal(1, rowsBefore)

	// Second revoke must not blow up on the UNIQUE primary-key constraint;
	// INSERT OR IGNORE keeps the original revoked_at unchanged.
	_, err = s.store.MarkIntegrationKeyRevoked(s.ctx, k.ID)
	s.Require().NoError(err)

	var rowsAfter int
	s.Require().NoError(s.store.db.QueryRowContext(s.ctx,
		`SELECT count(*) FROM jti_denylist WHERE jti = ?`, k.JTI,
	).Scan(&rowsAfter))
	s.Equal(1, rowsAfter, "second revoke must not insert a duplicate denylist row")
}

func (s *StoreSuite) TestDenylistSurvivesStoreReopen() {
	// Persisted, not in-memory: revoke through one connection, close it,
	// open a fresh connection on the same path, and the jti must still
	// report as revoked.
	path := filepath.Join(s.T().TempDir(), "persist.db")

	first, err := New(WithPath(path), WithBusyTimeout(time.Second))
	s.Require().NoError(err)
	s.Require().NoError(first.Migrate(s.ctx))

	prevStore := s.store
	s.store = first
	k := s.seedKey(denylistSeedOpts()...)
	s.store = prevStore

	_, err = first.MarkIntegrationKeyRevoked(s.ctx, k.ID)
	s.Require().NoError(err)
	s.Require().NoError(first.Close())

	reopened, err := New(WithPath(path), WithBusyTimeout(time.Second))
	s.Require().NoError(err)
	defer func() { _ = reopened.Close() }()

	got, err := reopened.IsRevoked(s.ctx, k.JTI)
	s.Require().NoError(err)
	s.True(got, "denylist entry must persist across a Close+reopen of the same .db file")
}
