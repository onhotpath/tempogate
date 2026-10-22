package postgres

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/onhotpath/tempogate/admin"
	"github.com/onhotpath/tempogate/oidc"
)

// The cases mirror state/sqlite/reaper_test.go: the two reapers keep the
// same rules, and only how they batch and lock differs.

// reapNow is the reaper's fake "now"; rows are written relative to it, so
// nothing depends on the wall clock.
var reapNow = time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)

const reapMaxLifetime = 30 * 24 * time.Hour

func testReaper(s *Store, opts ...ReaperOption) *Reaper {
	return NewReaper(s, append([]ReaperOption{
		WithReaperClock(func() time.Time { return reapNow }),
		WithReaperRefreshMaxLifetime(reapMaxLifetime),
	}, opts...)...)
}

func count(t *testing.T, s *Store, table string) int {
	t.Helper()
	var n int
	require.NoError(t, s.pool.QueryRow(t.Context(), `SELECT count(*) FROM `+table).Scan(&n))
	return n
}

func saveRefreshAt(t *testing.T, s *Store, family, token string, authTime, expiresAt time.Time, consumed bool) {
	t.Helper()
	require.NoError(t, s.SaveRefresh(t.Context(), oidc.Refresh{
		Token: token, JTI: "jti-" + token, ClientID: "ui", Email: "a@example.com",
		FamilyID: family, AuthTime: authTime, CreatedAt: authTime, ExpiresAt: expiresAt,
	}))
	if consumed {
		_, err := s.ConsumeRefresh(t.Context(), token, "ui", authTime)
		require.NoError(t, err)
	}
}

func saveKey(t *testing.T, s *Store, exp *time.Time) admin.IntegrationKey {
	t.Helper()
	k := admin.IntegrationKey{
		ID: uuid.Must(uuid.NewV7()).String(), Namespace: "default", Role: admin.RoleRead, Owner: "ops",
		JTI: uuid.NewString(), CreatedAt: reapNow.Add(-48 * time.Hour), ExpiresAt: exp,
	}
	require.NoError(t, s.SaveIntegrationKey(t.Context(), k))
	return k
}

func TestReaper(t *testing.T) {
	forEachServer(t, func(t *testing.T, srv testServer) {
		t.Run("DeletesOnlyExpiredShortLivedRows", func(t *testing.T) {
			s := newTestStore(t, srv)
			ctx := t.Context()
			expired, live := reapNow.Add(-time.Second), reapNow.Add(time.Minute)
			for i, exp := range []time.Time{expired, live, expired} {
				id := fmt.Sprintf("%d", i)
				require.NoError(t, s.SaveAuthRequest(ctx, oidc.AuthRequest{
					InternalState: "state-" + id, ClientID: "ui", Scope: "openid",
					CreatedAt: exp.Add(-5 * time.Minute), ExpiresAt: exp,
				}))
				require.NoError(t, s.SaveAuthCode(ctx, oidc.AuthCode{
					Code: "code-" + id, ClientID: "ui", Email: "a@example.com", Scope: "openid",
					CreatedAt: exp.Add(-time.Minute), ExpiresAt: exp,
				}))
				require.NoError(t, s.SaveDeviceCode(ctx, oidc.DeviceCode{
					Code: "device-" + id, UserCode: "USERCOD" + id, ClientID: "cli", Scope: "openid",
					IntervalSeconds: 5, CreatedAt: exp.Add(-15 * time.Minute), ExpiresAt: exp,
				}))
				require.NoError(t, s.SaveBrowserSession(ctx, oidc.BrowserSession{
					SID: "sid-" + id, Email: "a@example.com", CreatedAt: exp.Add(-5 * time.Minute), ExpiresAt: exp,
				}))
			}

			got, err := testReaper(s).Reap(ctx)
			require.NoError(t, err)
			require.Equal(t, map[string]int{
				"auth_requests": 2, "auth_codes": 2, "device_codes": 2, "browser_sessions": 2,
				"refresh_tokens": 0, "jti_denylist": 0,
			}, got)
			for _, table := range []string{"auth_requests", "auth_codes", "device_codes", "browser_sessions"} {
				require.Equalf(t, 1, count(t, s, table), "%s keeps its live row", table)
			}
			_, err = s.ConsumeAuthRequest(ctx, "state-1")
			require.NoError(t, err, "the live auth request survives")
		})

		t.Run("WorksInBatches", func(t *testing.T) {
			s := newTestStore(t, srv)
			for i := range 7 {
				require.NoError(t, s.SaveAuthRequest(t.Context(), oidc.AuthRequest{
					InternalState: fmt.Sprintf("s-%d", i), ClientID: "ui", Scope: "openid",
					CreatedAt: reapNow.Add(-time.Hour), ExpiresAt: reapNow.Add(-time.Minute),
				}))
			}
			got, err := testReaper(s, WithReaperBatchSize(2)).Reap(t.Context())
			require.NoError(t, err)
			require.Equal(t, 7, got["auth_requests"])
			require.Zero(t, count(t, s, "auth_requests"))
		})

		t.Run("ReplicasShareTheSweep", func(t *testing.T) {
			// Every replica runs a reaper; SKIP LOCKED lets them split the
			// rows between them instead of failing or deleting twice.
			s := newTestStore(t, srv)
			for i := range 200 {
				require.NoError(t, s.SaveAuthRequest(t.Context(), oidc.AuthRequest{
					InternalState: fmt.Sprintf("s-%d", i), ClientID: "ui", Scope: "openid",
					CreatedAt: reapNow.Add(-time.Hour), ExpiresAt: reapNow.Add(-time.Minute),
				}))
			}
			var (
				wg    sync.WaitGroup
				mu    sync.Mutex
				total int
			)
			for range 4 {
				wg.Go(func() {
					got, err := testReaper(s, WithReaperBatchSize(7)).Reap(t.Context())
					require.NoError(t, err)
					mu.Lock()
					total += got["auth_requests"]
					mu.Unlock()
				})
			}
			wg.Wait()
			require.Equal(t, 200, total, "each row is deleted exactly once")
			require.Zero(t, count(t, s, "auth_requests"))
		})

		t.Run("RefreshFamilies", func(t *testing.T) {
			s := newTestStore(t, srv)
			ctx := t.Context()
			recent := reapNow.Add(-24 * time.Hour)
			ancient := reapNow.Add(-reapMaxLifetime - time.Minute)
			past, future := reapNow.Add(-time.Minute), reapNow.Add(time.Hour)

			saveRefreshAt(t, s, "live", "live-1", recent, past, true)
			saveRefreshAt(t, s, "live", "live-2", recent, future, false)
			saveRefreshAt(t, s, "idle", "idle-1", recent, past, true)
			saveRefreshAt(t, s, "idle", "idle-2", recent, past, false)
			saveRefreshAt(t, s, "rotated", "rot-1", recent, past, true)
			saveRefreshAt(t, s, "rotated", "rot-2", recent, past, true)
			saveRefreshAt(t, s, "old", "old-1", ancient, past, true)
			saveRefreshAt(t, s, "old", "old-2", ancient, future, false)
			saveRefreshAt(t, s, "revoked", "rev-1", recent, past, false)
			saveRefreshAt(t, s, "revoked-live", "revl-1", recent, future, false)
			for _, f := range []string{"revoked", "revoked-live"} {
				_, err := s.RevokeRefreshFamily(ctx, f, recent)
				require.NoError(t, err)
			}

			got, err := testReaper(s, WithReaperBatchSize(2)).Reap(ctx)
			require.NoError(t, err)
			require.Equal(t, 5, got["refresh_tokens"])
			require.Equal(t, 5, count(t, s, "refresh_tokens"))

			for _, table := range []string{"refresh_tokens", "refresh_families"} {
				rows, err := s.pool.Query(ctx, `SELECT DISTINCT family_id FROM `+table+` ORDER BY family_id`)
				require.NoError(t, err)
				families, err := pgx.CollectRows(rows, pgx.RowTo[string])
				require.NoError(t, err)
				require.Equal(t, []string{"idle", "live", "revoked-live"}, families, table)
			}

			_, err = s.ConsumeRefresh(ctx, "live-1", "ui", reapNow)
			require.Truef(t, errors.Is(err, oidc.ErrRefreshReused), "got %v", err)
		})

		t.Run("RefreshFamilyAtItsAbsoluteExpiry", func(t *testing.T) {
			s := newTestStore(t, srv)
			authTime := reapNow.Add(-reapMaxLifetime + time.Minute)
			end := authTime.Add(reapMaxLifetime)
			saveRefreshAt(t, s, "fam", "t1", authTime, reapNow.Add(-time.Hour), true)
			saveRefreshAt(t, s, "fam", "t2", authTime, end, false)

			got, err := testReaper(s).Reap(t.Context())
			require.NoError(t, err)
			require.Zero(t, got["refresh_tokens"])

			later := testReaper(s, WithReaperClock(func() time.Time { return end.Add(time.Second) }))
			got, err = later.Reap(t.Context())
			require.NoError(t, err)
			require.Equal(t, 2, got["refresh_tokens"])
			require.Zero(t, count(t, s, "refresh_tokens"))
		})

		t.Run("NoAbsoluteLifetimeKeepsFamiliesWithALiveToken", func(t *testing.T) {
			s := newTestStore(t, srv)
			ancient := reapNow.Add(-365 * 24 * time.Hour)
			saveRefreshAt(t, s, "fam", "t1", ancient, reapNow.Add(time.Hour), false)
			got, err := testReaper(s, WithReaperRefreshMaxLifetime(0)).Reap(t.Context())
			require.NoError(t, err)
			require.Zero(t, got["refresh_tokens"])
		})

		t.Run("DenylistAfterTheTokenExpires", func(t *testing.T) {
			s := newTestStore(t, srv)
			ctx := t.Context()
			longGone := reapNow.Add(-denylistGrace - time.Minute)
			recently := reapNow.Add(-time.Minute)
			future := reapNow.Add(time.Hour)
			expired, withinGrace, notYet, forever := saveKey(t, s, &longGone), saveKey(t, s, &recently), saveKey(t, s, &future), saveKey(t, s, nil)
			for _, k := range []admin.IntegrationKey{expired, withinGrace, notYet, forever} {
				_, err := s.MarkIntegrationKeyRevoked(ctx, k.ID, reapNow)
				require.NoError(t, err)
			}
			_, err := s.pool.Exec(ctx, `INSERT INTO jti_denylist (jti, revoked_at) VALUES ('orphan', $1)`, reapNow)
			require.NoError(t, err)

			got, err := testReaper(s).Reap(ctx)
			require.NoError(t, err)
			require.Equal(t, 1, got["jti_denylist"])
			revoked, err := s.IsRevoked(ctx, expired.JTI)
			require.NoError(t, err)
			require.False(t, revoked, "the expired key's row is gone")
			require.Equal(t, 4, count(t, s, "jti_denylist"))
			require.Equal(t, 4, count(t, s, "integration_keys"), "integration keys are an audit record and are kept")
		})

		t.Run("RunSweepsUntilCancelled", func(t *testing.T) {
			s := newTestStore(t, srv)
			require.NoError(t, s.SaveAuthRequest(t.Context(), oidc.AuthRequest{
				InternalState: "old", ClientID: "ui", Scope: "openid",
				CreatedAt: reapNow.Add(-time.Hour), ExpiresAt: reapNow.Add(-time.Minute),
			}))
			core, logs := observer.New(zapcore.DebugLevel)
			r := testReaper(s, WithReaperInterval(10*time.Millisecond), WithReaperLogger(zap.New(core)))

			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan error, 1)
			go func() { done <- r.Run(ctx) }()
			require.Eventually(t, func() bool { return count(t, s, "auth_requests") == 0 }, 5*time.Second, 10*time.Millisecond)
			require.Eventually(t, func() bool { return logs.FilterMessage("reaped expired state").Len() > 0 }, 5*time.Second, 10*time.Millisecond)
			cancel()
			require.NoError(t, <-done)
		})

		t.Run("RunLogsErrorsAndKeepsGoing", func(t *testing.T) {
			obs := &recordingObserver{}
			s := newTestStore(t, srv, WithErrorObserver(obs))
			core, logs := observer.New(zapcore.WarnLevel)
			r := testReaper(s, WithReaperInterval(10*time.Millisecond), WithReaperLogger(zap.New(core)))
			s.pool.Close()

			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan error, 1)
			go func() { done <- r.Run(ctx) }()
			require.Eventually(t, func() bool { return logs.FilterMessage("reaping expired state failed").Len() >= 2 }, 5*time.Second, 10*time.Millisecond)
			cancel()
			require.NoError(t, <-done)
			require.Contains(t, obs.calls(), "reap")
		})
	})

	t.Run("DisabledWithZeroInterval", func(t *testing.T) {
		require.NoError(t, NewReaper(nil, WithReaperInterval(0)).Run(t.Context()))
	})
}
