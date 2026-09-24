package sqlite

import (
	"errors"
	"time"

	"github.com/onhotpath/tempogate/oidc"
)

// browser_sessions_test.go extends StoreSuite with the first-party browser
// session contract: save → lookup happy path, duplicate-sid sentinel,
// unknown-sid sentinel, and delete-then-lookup. SetupTest migrates the
// schema, so each test sees a clean table.

func (s *StoreSuite) browserSession(sid string) oidc.BrowserSession {
	now := time.Now().UTC().Truncate(time.Microsecond)
	return oidc.BrowserSession{
		SID:       sid,
		Email:     "alice@example.com",
		CreatedAt: now,
		ExpiresAt: now.Add(5 * time.Minute),
	}
}

func (s *StoreSuite) TestSaveBrowserSessionRoundTrip() {
	bs := s.browserSession("sid-1")
	s.Require().NoError(s.store.SaveBrowserSession(s.ctx, bs))

	got, err := s.store.LookupBrowserSession(s.ctx, bs.SID)
	s.Require().NoError(err)
	s.Equal(bs.SID, got.SID)
	s.Equal(bs.Email, got.Email)
	s.True(bs.CreatedAt.Equal(got.CreatedAt))
	s.True(bs.ExpiresAt.Equal(got.ExpiresAt))
}

func (s *StoreSuite) TestSaveBrowserSessionDuplicate() {
	bs := s.browserSession("sid-dup")
	s.Require().NoError(s.store.SaveBrowserSession(s.ctx, bs))

	err := s.store.SaveBrowserSession(s.ctx, bs)
	s.Require().Error(err)
	s.Truef(errors.Is(err, ErrDuplicateBrowserSession),
		"expected ErrDuplicateBrowserSession, got %v", err)
}

func (s *StoreSuite) TestLookupBrowserSessionUnknown() {
	_, err := s.store.LookupBrowserSession(s.ctx, "never-saved")
	s.Require().Error(err)
	s.Truef(errors.Is(err, oidc.ErrBrowserSessionNotFound),
		"expected oidc.ErrBrowserSessionNotFound, got %v", err)
}

func (s *StoreSuite) TestDeleteBrowserSession() {
	cases := []struct {
		name string
		sid  string
		seed bool
	}{
		{"existing", "sid-delete-1", true},
		// Best-effort delete: removing a row that was never written must not
		// surface an error to the caller, mirroring how sign-out and forced
		// revocation paths fan out to the store without re-checking existence.
		{"unknown is no-op", "never-saved", false},
	}

	for _, tc := range cases {
		s.Run(tc.name, func() {
			s.SetupTest()
			defer s.TearDownTest()

			if tc.seed {
				bs := s.browserSession(tc.sid)
				s.Require().NoError(s.store.SaveBrowserSession(s.ctx, bs))
			}

			s.Require().NoError(s.store.DeleteBrowserSession(s.ctx, tc.sid))

			_, err := s.store.LookupBrowserSession(s.ctx, tc.sid)
			s.Require().Error(err)
			s.Truef(errors.Is(err, oidc.ErrBrowserSessionNotFound),
				"expected oidc.ErrBrowserSessionNotFound after delete, got %v", err)
		})
	}
}
