package storetest

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/onhotpath/tempogate/oidc"
)

func deviceCode(code, userCode string) oidc.DeviceCode {
	return oidc.DeviceCode{
		Code:            code,
		UserCode:        userCode,
		ClientID:        "tempogate-cli",
		Scope:           "openid email",
		IntervalSeconds: 5,
		CreatedAt:       t0,
		ExpiresAt:       t0.Add(10 * time.Minute),
	}
}

var alice = oidc.Identity{Subject: "sub-alice", Email: "alice@example.com"}

func lookupDevice(t *testing.T, s Store, code string) oidc.DeviceCode {
	t.Helper()
	dc, err := s.LookupDeviceCodeByDeviceCode(t.Context(), code)
	require.NoError(t, err)
	return dc
}

func requireTimePtr(t *testing.T, want time.Time, got *time.Time, what string) {
	t.Helper()
	require.NotNil(t, got, what)
	requireTime(t, want, *got, what)
}

func deviceCodeCases() []testCase {
	return []testCase{
		{"DeviceCode/SaveAndLookUpByEitherCode", func(t *testing.T, b Backend) {
			want := deviceCode("dc-1", "ABCDEFGH")
			require.NoError(t, b.Store.SaveDeviceCode(t.Context(), want))

			got := lookupDevice(t, b.Store, want.Code)
			requireTime(t, want.CreatedAt, got.CreatedAt, "device created_at")
			requireTime(t, want.ExpiresAt, got.ExpiresAt, "device expires_at")
			got.CreatedAt, got.ExpiresAt = want.CreatedAt, want.ExpiresAt
			require.Equal(t, want, got)

			byUser, err := b.Store.LookupDeviceCodeByUserCode(t.Context(), want.UserCode)
			require.NoError(t, err)
			byUser.Code = want.Code // a store may keep only the device code's hash
			byUser.CreatedAt, byUser.ExpiresAt = want.CreatedAt, want.ExpiresAt
			require.Equal(t, want, byUser)
		}},
		{"DeviceCode/LookupUnknown", func(t *testing.T, b Backend) {
			_, err := b.Store.LookupDeviceCodeByDeviceCode(t.Context(), "never-issued")
			require.ErrorIs(t, err, oidc.ErrDeviceCodeNotFound)
			_, err = b.Store.LookupDeviceCodeByUserCode(t.Context(), "NOTISSUE")
			require.ErrorIs(t, err, oidc.ErrDeviceCodeNotFound)
		}},
		{"DeviceCode/DuplicateEitherCodeIsReported", func(t *testing.T, b Backend) {
			require.NoError(t, b.Store.SaveDeviceCode(t.Context(), deviceCode("dc-1", "ABCDEFGH")))
			require.ErrorIs(t, b.Store.SaveDeviceCode(t.Context(), deviceCode("dc-1", "HGFEDCBA")), oidc.ErrDuplicateDeviceCode)
			require.ErrorIs(t, b.Store.SaveDeviceCode(t.Context(), deviceCode("dc-2", "ABCDEFGH")), oidc.ErrDuplicateDeviceCode)
			_, err := b.Store.LookupDeviceCodeByDeviceCode(t.Context(), "dc-2")
			require.ErrorIs(t, err, oidc.ErrDeviceCodeNotFound)
		}},
		{"DeviceCode/PollEnforcesTheIntervalAndSlowsDown", func(t *testing.T, b Backend) {
			dc := deviceCode("dc-1", "ABCDEFGH")
			require.NoError(t, b.Store.SaveDeviceCode(t.Context(), dc))

			poll := func(at time.Time) bool {
				t.Helper()
				slow, err := b.Store.PollDeviceCode(t.Context(), dc.Code, at)
				require.NoError(t, err)
				return slow
			}
			require.False(t, poll(t0), "the first poll is well paced")
			requireTimePtr(t, t0, lookupDevice(t, b.Store, dc.Code).LastPolledAt, "last_polled_at")

			early := t0.Add(time.Second)
			require.True(t, poll(early), "a poll inside the interval is slow_down")
			got := lookupDevice(t, b.Store, dc.Code)
			require.Equal(t, 10, got.IntervalSeconds, "slow_down raises the interval by 5s")
			requireTimePtr(t, early, got.LastPolledAt, "a slow_down poll is recorded too")

			require.False(t, poll(early.Add(10*time.Second)), "exactly the raised interval later is well paced")
			require.True(t, poll(early.Add(19*time.Second)))
			require.Equal(t, 15, lookupDevice(t, b.Store, dc.Code).IntervalSeconds)
		}},
		{"DeviceCode/PollUnknown", func(t *testing.T, b Backend) {
			_, err := b.Store.PollDeviceCode(t.Context(), "never-issued", t0)
			require.ErrorIs(t, err, oidc.ErrDeviceCodeNotFound)
		}},
		{"DeviceCode/ConcurrentPollsHaveOneWellPaced", func(t *testing.T, b Backend) {
			require.NoError(t, b.Store.SaveDeviceCode(t.Context(), deviceCode("dc-1", "ABCDEFGH")))
			slow := make([]bool, racers)
			errs := race(func(i int) error {
				var err error
				slow[i], err = b.Store.PollDeviceCode(t.Context(), "dc-1", t0)
				return err
			})
			require.Equal(t, racers, winners(errs), "%v", errs)
			paced := 0
			for _, s := range slow {
				if !s {
					paced++
				}
			}
			require.Equal(t, 1, paced, "exactly one of the simultaneous polls is well paced")
			require.Equal(t, 5+5*(racers-1), lookupDevice(t, b.Store, "dc-1").IntervalSeconds)
		}},
		{"DeviceCode/ApproveOnce", func(t *testing.T, b Backend) {
			require.NoError(t, b.Store.SaveDeviceCode(t.Context(), deviceCode("dc-1", "ABCDEFGH")))
			at := t0.Add(time.Minute)
			require.NoError(t, b.Store.ApproveDeviceCode(t.Context(), "ABCDEFGH", alice, at))

			got := lookupDevice(t, b.Store, "dc-1")
			requireTimePtr(t, at, got.ApprovedAt, "approved_at")
			require.Nil(t, got.DeniedAt)
			require.Equal(t, alice.Subject, got.Subject)
			require.Equal(t, alice.Email, got.Email)

			require.ErrorIs(t, b.Store.ApproveDeviceCode(t.Context(), "ABCDEFGH", oidc.Identity{Subject: "sub-mallory"}, at),
				oidc.ErrDeviceCodeNotPending)
			require.ErrorIs(t, b.Store.DenyDeviceCode(t.Context(), "ABCDEFGH", at), oidc.ErrDeviceCodeNotPending)
			require.Equal(t, alice.Subject, lookupDevice(t, b.Store, "dc-1").Subject)
		}},
		{"DeviceCode/DenyOnce", func(t *testing.T, b Backend) {
			require.NoError(t, b.Store.SaveDeviceCode(t.Context(), deviceCode("dc-1", "ABCDEFGH")))
			at := t0.Add(time.Minute)
			require.NoError(t, b.Store.DenyDeviceCode(t.Context(), "ABCDEFGH", at))

			got := lookupDevice(t, b.Store, "dc-1")
			requireTimePtr(t, at, got.DeniedAt, "denied_at")
			require.Nil(t, got.ApprovedAt)
			require.ErrorIs(t, b.Store.ApproveDeviceCode(t.Context(), "ABCDEFGH", alice, at), oidc.ErrDeviceCodeNotPending)
			require.ErrorIs(t, b.Store.DenyDeviceCode(t.Context(), "ABCDEFGH", at), oidc.ErrDeviceCodeNotPending)
		}},
		{"DeviceCode/NoDecisionOnceExpiredOrUnknown", func(t *testing.T, b Backend) {
			dc := deviceCode("dc-1", "ABCDEFGH")
			require.NoError(t, b.Store.SaveDeviceCode(t.Context(), dc))

			require.ErrorIs(t, b.Store.ApproveDeviceCode(t.Context(), dc.UserCode, alice, dc.ExpiresAt), oidc.ErrDeviceCodeNotPending,
				"a code is expired from its expires_at on")
			require.ErrorIs(t, b.Store.DenyDeviceCode(t.Context(), dc.UserCode, dc.ExpiresAt.Add(time.Hour)), oidc.ErrDeviceCodeNotPending)
			require.ErrorIs(t, b.Store.ApproveDeviceCode(t.Context(), "NOTISSUE", alice, t0), oidc.ErrDeviceCodeNotPending)
			require.ErrorIs(t, b.Store.DenyDeviceCode(t.Context(), "NOTISSUE", t0), oidc.ErrDeviceCodeNotPending)

			got := lookupDevice(t, b.Store, dc.Code)
			require.Nil(t, got.ApprovedAt)
			require.Nil(t, got.DeniedAt)
		}},
		{"DeviceCode/ConcurrentDecisionsHaveOneWinner", func(t *testing.T, b Backend) {
			require.NoError(t, b.Store.SaveDeviceCode(t.Context(), deviceCode("dc-1", "ABCDEFGH")))
			errs := race(func(i int) error {
				if i%2 == 0 {
					return b.Store.ApproveDeviceCode(t.Context(), "ABCDEFGH", alice, t0)
				}
				return b.Store.DenyDeviceCode(t.Context(), "ABCDEFGH", t0)
			})
			require.Equal(t, 1, winners(errs), "%v", errs)
			for _, err := range errs {
				if err != nil {
					require.ErrorIs(t, err, oidc.ErrDeviceCodeNotPending)
				}
			}
			got := lookupDevice(t, b.Store, "dc-1")
			require.True(t, (got.ApprovedAt == nil) != (got.DeniedAt == nil), "exactly one decision is recorded")
		}},
		{"DeviceCode/ConsumeIsSingleUse", func(t *testing.T, b Backend) {
			require.NoError(t, b.Store.SaveDeviceCode(t.Context(), deviceCode("dc-1", "ABCDEFGH")))
			require.NoError(t, b.Store.ApproveDeviceCode(t.Context(), "ABCDEFGH", alice, t0))

			got, err := b.Store.ConsumeDeviceCode(t.Context(), "dc-1")
			require.NoError(t, err)
			require.Equal(t, "dc-1", got.Code)
			require.Equal(t, alice.Subject, got.Subject)
			requireTimePtr(t, t0, got.ApprovedAt, "approved_at")

			_, err = b.Store.ConsumeDeviceCode(t.Context(), "dc-1")
			require.ErrorIs(t, err, oidc.ErrDeviceCodeNotFound)
			_, err = b.Store.LookupDeviceCodeByUserCode(t.Context(), "ABCDEFGH")
			require.ErrorIs(t, err, oidc.ErrDeviceCodeNotFound, "the user code is free again")
		}},
		{"DeviceCode/ConcurrentConsumesHaveOneWinner", func(t *testing.T, b Backend) {
			require.NoError(t, b.Store.SaveDeviceCode(t.Context(), deviceCode("dc-1", "ABCDEFGH")))
			errs := race(func(int) error {
				_, err := b.Store.ConsumeDeviceCode(t.Context(), "dc-1")
				return err
			})
			require.Equal(t, 1, winners(errs), "%v", errs)
			for _, err := range errs {
				if err != nil {
					require.ErrorIs(t, err, oidc.ErrDeviceCodeNotFound)
				}
			}
		}},
	}
}
