package sqlite

import (
	"time"

	"github.com/google/uuid"

	"github.com/onhotpath/tempogate/admin"
)

// integration_keys_test.go extends StoreSuite (defined in store_test.go) with
// the admin.KeyRegistry contract: Save/ByID/List/MarkRevoked. The suite-level
// SetupTest reuses the shared sqlite fixture so we exercise the real driver
// and the embedded migration end-to-end.

func (s *StoreSuite) seedKey(opts ...admin.Option) admin.IntegrationKey {
	id, err := uuid.NewV7()
	s.Require().NoError(err)
	jti, err := uuid.NewV7()
	s.Require().NoError(err)

	k := admin.New(opts...)
	k.ID = id.String()
	k.JTI = jti.String()
	k.CreatedAt = time.Now().UTC().Truncate(time.Microsecond)

	s.Require().NoError(s.store.SaveIntegrationKey(s.ctx, *k))
	return *k
}

func (s *StoreSuite) TestIntegrationKeySaveAndByIDRoundTrip() {
	exp := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Microsecond)
	want := s.seedKey(
		admin.WithNamespace("payments"),
		admin.WithRole(admin.RoleWorker),
		admin.WithOwner("svc-recon"),
		admin.WithExpiresAt(&exp),
	)

	got, err := s.store.IntegrationKeyByID(s.ctx, want.ID)
	s.Require().NoError(err)

	s.Equal(want.ID, got.ID)
	s.Equal(want.Namespace, got.Namespace)
	s.Equal(want.Role, got.Role)
	s.Equal(want.Owner, got.Owner)
	s.Equal(want.JTI, got.JTI)
	s.True(want.CreatedAt.Equal(got.CreatedAt))
	s.Require().NotNil(got.ExpiresAt)
	s.True(exp.Equal(*got.ExpiresAt))
	s.Nil(got.RevokedAt)
}

func (s *StoreSuite) TestIntegrationKeySaveWithNilExpiresAt() {
	want := s.seedKey(
		admin.WithNamespace("payments"),
		admin.WithRole(admin.RoleRead),
		admin.WithOwner("svc"),
	)

	got, err := s.store.IntegrationKeyByID(s.ctx, want.ID)
	s.Require().NoError(err)
	s.Nil(got.ExpiresAt)
}

func (s *StoreSuite) TestIntegrationKeyByIDUnknownReturnsNotFound() {
	_, err := s.store.IntegrationKeyByID(s.ctx, uuid.NewString())
	s.Require().ErrorIs(err, admin.ErrIntegrationKeyNotFound)
}

func (s *StoreSuite) TestIntegrationKeyListFiltersByOwner() {
	a := s.seedKey(admin.WithNamespace("ns-1"), admin.WithRole(admin.RoleRead), admin.WithOwner("alice"))
	b := s.seedKey(admin.WithNamespace("ns-1"), admin.WithRole(admin.RoleRead), admin.WithOwner("bob"))
	c := s.seedKey(admin.WithNamespace("ns-2"), admin.WithRole(admin.RoleRead), admin.WithOwner("alice"))

	got, err := s.store.ListIntegrationKeys(s.ctx, admin.ListFilter{Owner: "alice", Limit: 10})
	s.Require().NoError(err)
	s.Len(got, 2)

	gotIDs := []string{got[0].ID, got[1].ID}
	s.Contains(gotIDs, a.ID)
	s.Contains(gotIDs, c.ID)
	s.NotContains(gotIDs, b.ID)
}

func (s *StoreSuite) TestIntegrationKeyListFiltersByNamespace() {
	a := s.seedKey(admin.WithNamespace("ns-1"), admin.WithRole(admin.RoleRead), admin.WithOwner("alice"))
	b := s.seedKey(admin.WithNamespace("ns-2"), admin.WithRole(admin.RoleRead), admin.WithOwner("bob"))

	got, err := s.store.ListIntegrationKeys(s.ctx, admin.ListFilter{Namespace: "ns-1", Limit: 10})
	s.Require().NoError(err)
	s.Len(got, 1)
	s.Equal(a.ID, got[0].ID)
	s.NotEqual(b.ID, got[0].ID)
}

func (s *StoreSuite) TestIntegrationKeyListFiltersByOwnerAndNamespace() {
	target := s.seedKey(admin.WithNamespace("ns-1"), admin.WithRole(admin.RoleRead), admin.WithOwner("alice"))
	_ = s.seedKey(admin.WithNamespace("ns-2"), admin.WithRole(admin.RoleRead), admin.WithOwner("alice"))
	_ = s.seedKey(admin.WithNamespace("ns-1"), admin.WithRole(admin.RoleRead), admin.WithOwner("bob"))

	got, err := s.store.ListIntegrationKeys(s.ctx, admin.ListFilter{Owner: "alice", Namespace: "ns-1", Limit: 10})
	s.Require().NoError(err)
	s.Len(got, 1)
	s.Equal(target.ID, got[0].ID)
}

func (s *StoreSuite) TestIntegrationKeyListOrdersByIDDesc() {
	a := s.seedKey(admin.WithNamespace("ns"), admin.WithRole(admin.RoleRead), admin.WithOwner("o"))
	// UUIDv7 within a single millisecond uses random low bits, so two
	// back-to-back NewV7s can come out in any order. Sleep ~2ms to guarantee
	// the second id is lexicographically greater than the first and the
	// assertion below tests ordering rather than the random-bit lottery.
	time.Sleep(2 * time.Millisecond)
	b := s.seedKey(admin.WithNamespace("ns"), admin.WithRole(admin.RoleRead), admin.WithOwner("o"))
	time.Sleep(2 * time.Millisecond)
	c := s.seedKey(admin.WithNamespace("ns"), admin.WithRole(admin.RoleRead), admin.WithOwner("o"))

	got, err := s.store.ListIntegrationKeys(s.ctx, admin.ListFilter{Limit: 10})
	s.Require().NoError(err)
	s.Len(got, 3)

	// newest first
	s.Equal(c.ID, got[0].ID)
	s.Equal(b.ID, got[1].ID)
	s.Equal(a.ID, got[2].ID)
}

func (s *StoreSuite) TestIntegrationKeyListPaginatesViaCursor() {
	ids := make([]string, 0, 5)
	for range 5 {
		k := s.seedKey(admin.WithNamespace("ns"), admin.WithRole(admin.RoleRead), admin.WithOwner("o"))
		ids = append(ids, k.ID)
		time.Sleep(2 * time.Millisecond)
	}

	// id DESC, so the first page contains the last-seeded keys.
	page1, err := s.store.ListIntegrationKeys(s.ctx, admin.ListFilter{Limit: 2})
	s.Require().NoError(err)
	// limit=2 binds limit+1=3 at the SQL layer — store returns up to limit+1
	// so the handler can detect "has more". Two trimmed page items + a peek.
	s.Len(page1, 3)
	s.Equal(ids[4], page1[0].ID)
	s.Equal(ids[3], page1[1].ID)
	s.Equal(ids[2], page1[2].ID) // the peek

	page2, err := s.store.ListIntegrationKeys(s.ctx, admin.ListFilter{Limit: 2, Cursor: page1[1].ID})
	s.Require().NoError(err)
	s.Len(page2, 3)
	s.Equal(ids[2], page2[0].ID)
	s.Equal(ids[1], page2[1].ID)
	s.Equal(ids[0], page2[2].ID) // the peek

	page3, err := s.store.ListIntegrationKeys(s.ctx, admin.ListFilter{Limit: 2, Cursor: page2[1].ID})
	s.Require().NoError(err)
	s.Len(page3, 1)
	s.Equal(ids[0], page3[0].ID) // last page, no peek available
}

func (s *StoreSuite) TestIntegrationKeyListNeverDuplicatesOrSkipsUnderConcurrentInsert() {
	a := s.seedKey(admin.WithNamespace("ns"), admin.WithRole(admin.RoleRead), admin.WithOwner("o"))
	time.Sleep(2 * time.Millisecond)
	b := s.seedKey(admin.WithNamespace("ns"), admin.WithRole(admin.RoleRead), admin.WithOwner("o"))

	page1, err := s.store.ListIntegrationKeys(s.ctx, admin.ListFilter{Limit: 1})
	s.Require().NoError(err)
	s.Len(page1, 2)
	s.Equal(b.ID, page1[0].ID)

	// Concurrent insert lands a row with a HIGHER id than anything paginated
	// so far — id DESC means it appears on a future first-page call, never
	// between the two pages of an in-progress iteration.
	time.Sleep(2 * time.Millisecond)
	_ = s.seedKey(admin.WithNamespace("ns"), admin.WithRole(admin.RoleRead), admin.WithOwner("o"))

	page2, err := s.store.ListIntegrationKeys(s.ctx, admin.ListFilter{Limit: 1, Cursor: page1[0].ID})
	s.Require().NoError(err)
	s.Len(page2, 1)
	s.Equal(a.ID, page2[0].ID)
}

func (s *StoreSuite) TestMarkRevokedReturnsJTIAndStampsRevokedAt() {
	k := s.seedKey(admin.WithNamespace("ns"), admin.WithRole(admin.RoleRead), admin.WithOwner("o"))

	gotJTI, err := s.store.MarkIntegrationKeyRevoked(s.ctx, k.ID)
	s.Require().NoError(err)
	s.Equal(k.JTI, gotJTI)

	got, err := s.store.IntegrationKeyByID(s.ctx, k.ID)
	s.Require().NoError(err)
	s.Require().NotNil(got.RevokedAt)
	s.False(got.RevokedAt.IsZero())
}

func (s *StoreSuite) TestMarkRevokedIsIdempotent() {
	k := s.seedKey(admin.WithNamespace("ns"), admin.WithRole(admin.RoleRead), admin.WithOwner("o"))

	first, err := s.store.MarkIntegrationKeyRevoked(s.ctx, k.ID)
	s.Require().NoError(err)

	row, err := s.store.IntegrationKeyByID(s.ctx, k.ID)
	s.Require().NoError(err)
	stampedAt := *row.RevokedAt

	time.Sleep(2 * time.Millisecond)
	second, err := s.store.MarkIntegrationKeyRevoked(s.ctx, k.ID)
	s.Require().NoError(err)
	s.Equal(first, second, "second call must return the same jti")

	again, err := s.store.IntegrationKeyByID(s.ctx, k.ID)
	s.Require().NoError(err)
	s.Require().NotNil(again.RevokedAt)
	s.True(stampedAt.Equal(*again.RevokedAt), "revoked_at must not be re-stamped on second call")
}

func (s *StoreSuite) TestMarkRevokedUnknownIDReturnsNotFound() {
	_, err := s.store.MarkIntegrationKeyRevoked(s.ctx, uuid.NewString())
	s.Require().ErrorIs(err, admin.ErrIntegrationKeyNotFound)
}

// TestListNormalisesNonPositiveLimit locks the store-side boundary clamp.
// The HTTP handler already normalises Limit, but a direct caller (cleanup
// job, future internal tool) that passes Limit=0 or Limit=-1 must NOT cause
// SQL LIMIT 0 (silent zero results that mask a bug) — the store falls back
// to its own default page size in that case.
func (s *StoreSuite) TestListNormalisesNonPositiveLimit() {
	for i := 0; i < 3; i++ {
		s.seedKey(admin.WithNamespace("ns"), admin.WithRole(admin.RoleRead), admin.WithOwner("o"))
		time.Sleep(2 * time.Millisecond)
	}

	cases := []struct {
		name  string
		limit int
	}{
		{"zero", 0},
		{"negative", -1},
		{"large negative", -10000},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			got, err := s.store.ListIntegrationKeys(s.ctx, admin.ListFilter{Limit: tc.limit})
			s.Require().NoError(err)
			s.Len(got, 3, "non-positive limit must fall back to a sane default, not return zero rows")
		})
	}
}
