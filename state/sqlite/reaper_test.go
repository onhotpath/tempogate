package sqlite

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/onhotpath/tempogate/admin"
	"github.com/onhotpath/tempogate/oidc"
)

// reapNow is the reaper's fake "now"; rows are written relative to it, so
// nothing depends on the wall clock.
var reapNow = time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)

const reapMaxLifetime = 30 * 24 * time.Hour

func (s *StoreSuite) reaper(opts ...ReaperOption) *Reaper {
	return NewReaper(s.store, append([]ReaperOption{
		WithReaperClock(func() time.Time { return reapNow }),
		WithReaperRefreshMaxLifetime(reapMaxLifetime),
	}, opts...)...)
}

func (s *StoreSuite) count(table string) int {
	var n int
	s.Require().NoError(s.store.db.QueryRowContext(s.ctx, `SELECT count(*) FROM `+table).Scan(&n))
	return n
}

// TestReapDeletesOnlyExpiredShortLivedRows covers the tables an anonymous
// caller can grow (auth_requests, device_codes) and the other short-lived
// ones (auth_codes, browser_sessions).
func (s *StoreSuite) TestReapDeletesOnlyExpiredShortLivedRows() {
	expired, live := reapNow.Add(-time.Second), reapNow.Add(time.Minute)
	for i, exp := range []time.Time{expired, live, expired} {
		id := fmt.Sprintf("%d", i)
		s.Require().NoError(s.store.SaveAuthRequest(s.ctx, oidc.AuthRequest{
			InternalState: "state-" + id, ClientID: "ui", Scope: "openid",
			CreatedAt: exp.Add(-5 * time.Minute), ExpiresAt: exp,
		}))
		s.Require().NoError(s.store.SaveAuthCode(s.ctx, oidc.AuthCode{
			Code: "code-" + id, ClientID: "ui", Email: "a@example.com", Scope: "openid",
			CreatedAt: exp.Add(-time.Minute), ExpiresAt: exp,
		}))
		s.Require().NoError(s.store.SaveDeviceCode(s.ctx, oidc.DeviceCode{
			Code: "device-" + id, UserCode: "USERCOD" + id, ClientID: "cli", Scope: "openid",
			IntervalSeconds: 5, CreatedAt: exp.Add(-15 * time.Minute), ExpiresAt: exp,
		}))
		s.Require().NoError(s.store.SaveBrowserSession(s.ctx, oidc.BrowserSession{
			SID: "sid-" + id, Email: "a@example.com", CreatedAt: exp.Add(-5 * time.Minute), ExpiresAt: exp,
		}))
	}

	got, err := s.reaper().Reap(s.ctx)
	s.Require().NoError(err)
	s.Equal(map[string]int{
		"auth_requests": 2, "auth_codes": 2, "device_codes": 2, "browser_sessions": 2,
		"refresh_tokens": 0, "jti_denylist": 0,
	}, got)

	for _, table := range []string{"auth_requests", "auth_codes", "device_codes", "browser_sessions"} {
		s.Equalf(1, s.count(table), "%s keeps its live row", table)
	}
	_, err = s.store.ConsumeAuthRequest(s.ctx, "state-1")
	s.NoError(err, "the live auth request survives")
	_, err = s.store.LookupBrowserSession(s.ctx, "sid-1")
	s.NoError(err, "the live browser session survives")
	_, err = s.store.LookupDeviceCodeByDeviceCode(s.ctx, "device-1")
	s.NoError(err, "the live device code survives")
}

// TestReapWorksInBatches: rows are deleted a batch at a time so the single
// connection is never held for the whole sweep.
func (s *StoreSuite) TestReapWorksInBatches() {
	for i := range 7 {
		s.Require().NoError(s.store.SaveAuthRequest(s.ctx, oidc.AuthRequest{
			InternalState: fmt.Sprintf("s-%d", i), ClientID: "ui", Scope: "openid",
			CreatedAt: reapNow.Add(-time.Hour), ExpiresAt: reapNow.Add(-time.Minute),
		}))
	}
	got, err := s.reaper(WithReaperBatchSize(2)).Reap(s.ctx)
	s.Require().NoError(err)
	s.Equal(7, got["auth_requests"])
	s.Zero(s.count("auth_requests"))
}

// saveRefreshAt writes one refresh-token row of family, consumed or revoked
// as asked, with explicit times relative to reapNow.
func (s *StoreSuite) saveRefreshAt(family, token string, authTime, expiresAt time.Time, consumed bool) {
	s.Require().NoError(s.store.SaveRefresh(s.ctx, oidc.Refresh{
		Token: token, JTI: "jti-" + token, ClientID: "ui", Email: "a@example.com",
		FamilyID: family, AuthTime: authTime, CreatedAt: authTime, ExpiresAt: expiresAt,
	}))
	if consumed {
		_, err := s.store.ConsumeRefresh(s.ctx, token, "ui", authTime)
		s.Require().NoError(err)
	}
}

// TestReapRefreshFamilies pins the tombstone rule from migration 0011: a
// consumed token is what lets a replay be recognised, so a family's rows go
// only when every row is dead (past the absolute lifetime, or expired and
// consumed or revoked). Reaping a tombstone while its family has a live
// token would turn a detected replay into a plain "unknown token" and leave
// the thief's sibling token alive.
func (s *StoreSuite) TestReapRefreshFamilies() {
	recent := reapNow.Add(-24 * time.Hour)
	ancient := reapNow.Add(-reapMaxLifetime - time.Minute)
	past, future := reapNow.Add(-time.Minute), reapNow.Add(time.Hour)

	// live: an expired tombstone and its live successor. Kept whole.
	s.saveRefreshAt("live", "live-1", recent, past, true)
	s.saveRefreshAt("live", "live-2", recent, future, false)
	// idle: everything expired, but the newest token was never consumed
	// and the absolute lifetime has not passed. Kept.
	s.saveRefreshAt("idle", "idle-1", recent, past, true)
	s.saveRefreshAt("idle", "idle-2", recent, past, false)
	// rotated: every token consumed and expired. Reaped.
	s.saveRefreshAt("rotated", "rot-1", recent, past, true)
	s.saveRefreshAt("rotated", "rot-2", recent, past, true)
	// old: past the absolute lifetime, even with an unexpired row (minted
	// before OIDC_REFRESH_MAX_LIFETIME was lowered). Reaped.
	s.saveRefreshAt("old", "old-1", ancient, past, true)
	s.saveRefreshAt("old", "old-2", ancient, future, false)
	// revoked: expired and revoked. Reaped.
	s.saveRefreshAt("revoked", "rev-1", recent, past, false)
	// revoked-live: revoked but not yet expired. Kept until it expires.
	s.saveRefreshAt("revoked-live", "revl-1", recent, future, false)
	for _, f := range []string{"revoked", "revoked-live"} {
		_, err := s.store.RevokeRefreshFamily(s.ctx, f, recent)
		s.Require().NoError(err)
	}

	got, err := s.reaper().Reap(s.ctx)
	s.Require().NoError(err)
	s.Equal(5, got["refresh_tokens"])
	s.Equal(5, s.count("refresh_tokens"))

	var families []string
	rows, err := s.store.db.QueryContext(s.ctx, `SELECT DISTINCT family_id FROM refresh_tokens ORDER BY family_id`)
	s.Require().NoError(err)
	for rows.Next() {
		var f string
		s.Require().NoError(rows.Scan(&f))
		families = append(families, f)
	}
	s.Require().NoError(rows.Err())
	s.Require().NoError(rows.Close())
	s.Equal([]string{"idle", "live", "revoked-live"}, families)

	// Reuse detection still works on the kept tombstone.
	_, err = s.store.ConsumeRefresh(s.ctx, "live-1", "ui", reapNow)
	s.Truef(errors.Is(err, oidc.ErrRefreshReused), "got %v", err)
}

// TestReapRefreshFamilyAtItsAbsoluteExpiry: a family with a live token is
// kept right up to auth_time + max lifetime, then goes as a whole.
func (s *StoreSuite) TestReapRefreshFamilyAtItsAbsoluteExpiry() {
	authTime := reapNow.Add(-reapMaxLifetime + time.Minute)
	end := authTime.Add(reapMaxLifetime)
	s.saveRefreshAt("fam", "t1", authTime, reapNow.Add(-time.Hour), true)
	s.saveRefreshAt("fam", "t2", authTime, end, false)

	got, err := s.reaper().Reap(s.ctx)
	s.Require().NoError(err)
	s.Zero(got["refresh_tokens"])
	_, err = s.store.ConsumeRefresh(s.ctx, "t1", "ui", reapNow)
	s.Truef(errors.Is(err, oidc.ErrRefreshReused), "replay still detected before the family's end, got %v", err)

	later := s.reaper(WithReaperClock(func() time.Time { return end.Add(time.Second) }))
	got, err = later.Reap(s.ctx)
	s.Require().NoError(err)
	s.Equal(2, got["refresh_tokens"])
	s.Zero(s.count("refresh_tokens"))
}

// TestReapDenylistAfterTheTokenExpires: a denylist row only matters while
// the revoked JWT could still verify, i.e. until its exp (the integration
// key's expires_at) plus a grace for clock skew. Keys without an expiry
// are revoked forever.
func (s *StoreSuite) TestReapDenylistAfterTheTokenExpires() {
	longGone := reapNow.Add(-denylistGrace - time.Minute)
	recently := reapNow.Add(-time.Minute)
	future := reapNow.Add(time.Hour)

	key := func(exp *time.Time) admin.IntegrationKey {
		return s.seedKey(admin.WithNamespace("default"), admin.WithRole(admin.RoleRead), admin.WithOwner("ops"), admin.WithExpiresAt(exp))
	}
	expired, withinGrace, notYet, forever := key(&longGone), key(&recently), key(&future), key(nil)
	for _, k := range []admin.IntegrationKey{expired, withinGrace, notYet, forever} {
		_, err := s.store.MarkIntegrationKeyRevoked(s.ctx, k.ID, time.Now().UTC())
		s.Require().NoError(err)
	}
	// A denylisted jti without a key row (not written today) is kept: its
	// expiry is unknown.
	_, err := s.store.db.ExecContext(s.ctx, `INSERT INTO jti_denylist (jti, revoked_at) VALUES ('orphan', ?)`, reapNow)
	s.Require().NoError(err)

	got, err := s.reaper().Reap(s.ctx)
	s.Require().NoError(err)
	s.Equal(1, got["jti_denylist"])

	for _, k := range []admin.IntegrationKey{withinGrace, notYet, forever} {
		revoked, err := s.store.IsRevoked(s.ctx, k.JTI)
		s.Require().NoError(err)
		s.Truef(revoked, "key %s stays denylisted", k.ID)
	}
	revoked, err := s.store.IsRevoked(s.ctx, expired.JTI)
	s.Require().NoError(err)
	s.False(revoked, "the expired key's row is gone")
	s.Equal(4, s.count("jti_denylist"))
	s.Equal(4, s.count("integration_keys"), "integration keys themselves are an audit record and are kept")
}

func (s *StoreSuite) TestReaperRunSweepsUntilCancelled() {
	s.Require().NoError(s.store.SaveAuthRequest(s.ctx, oidc.AuthRequest{
		InternalState: "old", ClientID: "ui", Scope: "openid",
		CreatedAt: reapNow.Add(-time.Hour), ExpiresAt: reapNow.Add(-time.Minute),
	}))
	core, logs := observer.New(zapcore.DebugLevel)
	r := s.reaper(WithReaperInterval(10*time.Millisecond), WithReaperLogger(zap.New(core)))

	ctx, cancel := context.WithCancel(s.ctx)
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()

	s.Eventually(func() bool { return s.count("auth_requests") == 0 }, 5*time.Second, 10*time.Millisecond)
	s.Eventually(func() bool { return logs.FilterMessage("reaped expired state").Len() > 0 }, 5*time.Second, 10*time.Millisecond)

	cancel()
	select {
	case err := <-done:
		s.NoError(err)
	case <-time.After(5 * time.Second):
		s.Fail("Run did not return after cancel")
	}
}

func (s *StoreSuite) TestReaperRunLogsErrorsAndKeepsGoing() {
	core, logs := observer.New(zapcore.WarnLevel)
	r := s.reaper(WithReaperInterval(10*time.Millisecond), WithReaperLogger(zap.New(core)))
	s.Require().NoError(s.store.Close())
	s.store = nil

	ctx, cancel := context.WithCancel(s.ctx)
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	s.Eventually(func() bool { return logs.FilterMessage("reaping expired state failed").Len() >= 2 }, 5*time.Second, 10*time.Millisecond,
		"a failed sweep is logged and retried on the next tick")
	cancel()
	s.NoError(<-done)
}

func (s *StoreSuite) TestReaperDisabledWithZeroInterval() {
	r := s.reaper(WithReaperInterval(0))
	done := make(chan error, 1)
	go func() { done <- r.Run(context.Background()) }()
	select {
	case err := <-done:
		s.NoError(err)
	case <-time.After(5 * time.Second):
		s.Fail("a disabled reaper returns at once")
	}
}
