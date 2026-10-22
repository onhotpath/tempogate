package sqlite

import (
	"errors"
	"time"

	"github.com/onhotpath/tempogate/admin"
)

// TestAdminSessionStore drives the production admin.SessionStore shim, so
// the HTTP routes provably call the same store methods as `tempogate
// sessions`.
func (s *StoreSuite) TestAdminSessionStore() {
	st := newAdminSessionStore(s.store)
	now := time.Now().UTC()
	s.saveFamily("fam-a", "alice@example.com", "a1")
	s.saveFamily("fam-b", "bob@example.com", "b1")
	s.saveFamily("fam-c", "carol@example.com", "c1")

	all, err := st.List(s.ctx, admin.SessionFilter{}, now)
	s.Require().NoError(err)
	s.Len(all, 3)
	bob, err := st.List(s.ctx, admin.SessionFilter{Email: "BOB@example.com", Subject: "google-sub-alice"}, now)
	s.Require().NoError(err)
	s.Require().Len(bob, 1)
	s.Equal(admin.Session{
		FamilyID: "fam-b", ClientID: "ui", Subject: "google-sub-alice", Email: "bob@example.com",
		AuthTime: bob[0].AuthTime, RotatedAt: bob[0].RotatedAt, ExpiresAt: bob[0].ExpiresAt,
	}, bob[0])

	n, err := st.RevokeFamily(s.ctx, "fam-a", now)
	s.Require().NoError(err)
	s.Equal(1, n)
	_, err = st.RevokeFamily(s.ctx, "fam-unknown", now)
	s.True(errors.Is(err, admin.ErrSessionNotFound))

	n, err = st.RevokeEmail(s.ctx, "bob@example.com", now)
	s.Require().NoError(err)
	s.Equal(1, n)

	n, err = st.RevokeSubject(s.ctx, "google-sub-alice", now)
	s.Require().NoError(err)
	s.Equal(1, n, "only carol's session was still live")

	s.Require().NoError(s.store.Close())
	_, err = st.List(s.ctx, admin.SessionFilter{}, now)
	s.Error(err)
}
