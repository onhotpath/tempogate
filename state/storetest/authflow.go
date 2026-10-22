package storetest

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/onhotpath/tempogate/oidc"
)

func authRequest(state string) oidc.AuthRequest {
	return oidc.AuthRequest{
		InternalState:       state,
		ClientID:            "temporal-ui",
		RedirectURI:         "https://temporal.example.com/auth/sso/callback",
		Scope:               "openid email",
		ClientState:         "client-state",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
		Nonce:               "nonce",
		CreatedAt:           t0,
		// Long expired by the wall clock: expiry is the caller's concern,
		// so the store still hands the row back.
		ExpiresAt: t0.Add(10 * time.Minute),
	}
}

func authCode(code string) oidc.AuthCode {
	return oidc.AuthCode{
		Code:                code,
		ClientID:            "temporal-ui",
		RedirectURI:         "https://temporal.example.com/auth/sso/callback",
		Subject:             "sub-alice",
		Email:               "alice@example.com",
		Scope:               "openid email",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
		Nonce:               "nonce",
		CreatedAt:           t0,
		ExpiresAt:           t0.Add(time.Minute),
	}
}

func browserSession(sid string) oidc.BrowserSession {
	return oidc.BrowserSession{
		SID:       sid,
		Subject:   "sub-alice",
		Email:     "alice@example.com",
		CreatedAt: t0,
		ExpiresAt: t0.Add(5 * time.Minute),
	}
}

func requireAuthRequest(t *testing.T, want, got oidc.AuthRequest) {
	t.Helper()
	requireTime(t, want.CreatedAt, got.CreatedAt, "auth request created_at")
	requireTime(t, want.ExpiresAt, got.ExpiresAt, "auth request expires_at")
	got.CreatedAt, got.ExpiresAt = want.CreatedAt, want.ExpiresAt
	require.Equal(t, want, got)
}

// requireAuthCode compares the fields every consume returns; the replay
// path needs only the identity and the family, so it is checked with
// requireAuthCodeIdentity instead.
func requireAuthCode(t *testing.T, want, got oidc.AuthCode) {
	t.Helper()
	requireTime(t, want.CreatedAt, got.CreatedAt, "auth code created_at")
	requireTime(t, want.ExpiresAt, got.ExpiresAt, "auth code expires_at")
	got.CreatedAt, got.ExpiresAt = want.CreatedAt, want.ExpiresAt
	require.Equal(t, want, got)
}

func requireAuthCodeIdentity(t *testing.T, want, got oidc.AuthCode) {
	t.Helper()
	require.Equal(t, want.Code, got.Code)
	require.Equal(t, want.ClientID, got.ClientID)
	require.Equal(t, want.RedirectURI, got.RedirectURI)
	require.Equal(t, want.Subject, got.Subject)
	require.Equal(t, want.Email, got.Email)
	require.Equal(t, want.FamilyID, got.FamilyID)
	requireTime(t, want.ExpiresAt, got.ExpiresAt, "auth code expires_at")
}

func authFlowCases() []testCase {
	return []testCase{
		{"AuthRequest/ConsumeIsSingleUse", func(t *testing.T, b Backend) {
			want := authRequest("state-1")
			require.NoError(t, b.Store.SaveAuthRequest(t.Context(), want))

			got, err := b.Store.ConsumeAuthRequest(t.Context(), want.InternalState)
			require.NoError(t, err)
			requireAuthRequest(t, want, got)

			_, err = b.Store.ConsumeAuthRequest(t.Context(), want.InternalState)
			require.ErrorIs(t, err, oidc.ErrAuthRequestNotFound)
		}},
		{"AuthRequest/ConsumeUnknown", func(t *testing.T, b Backend) {
			_, err := b.Store.ConsumeAuthRequest(t.Context(), "never-issued")
			require.ErrorIs(t, err, oidc.ErrAuthRequestNotFound)
		}},
		{"AuthRequest/DuplicateStateFailsAndKeepsTheOriginal", func(t *testing.T, b Backend) {
			first := authRequest("state-1")
			require.NoError(t, b.Store.SaveAuthRequest(t.Context(), first))
			dup := authRequest("state-1")
			dup.ClientID = "other"
			require.Error(t, b.Store.SaveAuthRequest(t.Context(), dup))

			got, err := b.Store.ConsumeAuthRequest(t.Context(), "state-1")
			require.NoError(t, err)
			requireAuthRequest(t, first, got)
		}},
		{"AuthRequest/ConcurrentConsumesHaveOneWinner", func(t *testing.T, b Backend) {
			require.NoError(t, b.Store.SaveAuthRequest(t.Context(), authRequest("hot")))
			errs := race(func(int) error {
				_, err := b.Store.ConsumeAuthRequest(t.Context(), "hot")
				return err
			})
			require.Equal(t, 1, winners(errs), "%v", errs)
			for _, err := range errs {
				if err != nil {
					require.ErrorIs(t, err, oidc.ErrAuthRequestNotFound)
				}
			}
		}},
		{"AuthCode/ConsumeRecordsTheFamilyAndLeavesATombstone", func(t *testing.T, b Backend) {
			want := authCode("code-1")
			require.NoError(t, b.Store.SaveAuthCode(t.Context(), want))

			got, err := b.Store.ConsumeAuthCode(t.Context(), want.Code, "fam-1", t0.Add(time.Second))
			require.NoError(t, err)
			want.FamilyID = "fam-1"
			requireAuthCode(t, want, got)

			replay, err := b.Store.ConsumeAuthCode(t.Context(), want.Code, "fam-2", t0.Add(2*time.Second))
			require.ErrorIs(t, err, oidc.ErrAuthCodeReused)
			requireAuthCodeIdentity(t, want, replay)
		}},
		{"AuthCode/ConsumeUnknown", func(t *testing.T, b Backend) {
			_, err := b.Store.ConsumeAuthCode(t.Context(), "never-issued", "fam", t0)
			require.ErrorIs(t, err, oidc.ErrAuthCodeNotFound)
		}},
		{"AuthCode/DuplicateCodeFailsAndKeepsTheOriginal", func(t *testing.T, b Backend) {
			first := authCode("code-1")
			require.NoError(t, b.Store.SaveAuthCode(t.Context(), first))
			dup := authCode("code-1")
			dup.Email = "mallory@example.com"
			require.Error(t, b.Store.SaveAuthCode(t.Context(), dup))

			got, err := b.Store.ConsumeAuthCode(t.Context(), "code-1", "fam", t0)
			require.NoError(t, err)
			require.Equal(t, first.Email, got.Email)
		}},
		{"AuthCode/ConcurrentConsumesHaveOneWinner", func(t *testing.T, b Backend) {
			require.NoError(t, b.Store.SaveAuthCode(t.Context(), authCode("hot")))
			families := make([]string, racers)
			errs := race(func(i int) error {
				got, err := b.Store.ConsumeAuthCode(t.Context(), "hot", fmt.Sprintf("fam-%02d", i), t0)
				families[i] = got.FamilyID
				return err
			})
			require.Equal(t, 1, winners(errs), "%v", errs)
			winner := ""
			for i, err := range errs {
				if err == nil {
					winner = families[i]
				}
			}
			require.NotEmpty(t, winner)
			for i, err := range errs {
				if err != nil {
					require.ErrorIs(t, err, oidc.ErrAuthCodeReused)
					require.Equal(t, winner, families[i], "every replay names the winning redemption's family")
				}
			}
		}},
		{"BrowserSession/SaveLookupDelete", func(t *testing.T, b Backend) {
			want := browserSession("sid-1")
			require.NoError(t, b.Store.SaveBrowserSession(t.Context(), want))

			got, err := b.Store.LookupBrowserSession(t.Context(), want.SID)
			require.NoError(t, err)
			requireTime(t, want.CreatedAt, got.CreatedAt, "session created_at")
			requireTime(t, want.ExpiresAt, got.ExpiresAt, "session expires_at")
			got.CreatedAt, got.ExpiresAt = want.CreatedAt, want.ExpiresAt
			require.Equal(t, want, got)

			require.NoError(t, b.Store.DeleteBrowserSession(t.Context(), want.SID))
			_, err = b.Store.LookupBrowserSession(t.Context(), want.SID)
			require.ErrorIs(t, err, oidc.ErrBrowserSessionNotFound)
			require.NoError(t, b.Store.DeleteBrowserSession(t.Context(), want.SID), "deleting an unknown sid is a no-op")
		}},
		{"BrowserSession/LookupUnknown", func(t *testing.T, b Backend) {
			_, err := b.Store.LookupBrowserSession(t.Context(), "never-minted")
			require.ErrorIs(t, err, oidc.ErrBrowserSessionNotFound)
		}},
		{"BrowserSession/DuplicateSIDFailsAndKeepsTheOriginal", func(t *testing.T, b Backend) {
			first := browserSession("sid-1")
			require.NoError(t, b.Store.SaveBrowserSession(t.Context(), first))
			dup := browserSession("sid-1")
			dup.Email = "mallory@example.com"
			require.Error(t, b.Store.SaveBrowserSession(t.Context(), dup))

			got, err := b.Store.LookupBrowserSession(t.Context(), "sid-1")
			require.NoError(t, err)
			require.Equal(t, first.Email, got.Email)
		}},
		{"StoreProbe/HealthyStoreIsReady", func(t *testing.T, b Backend) {
			require.NoError(t, b.Store.Probe(t.Context()))
		}},
		{"Errors/NotFoundNeverEchoesTheSecret", func(t *testing.T, b Backend) {
			// Lookup keys are bearer secrets and error text ends up in logs.
			const secret = "bearer-secret-value"
			for _, err := range []error{
				func() error { _, err := b.Store.ConsumeAuthRequest(t.Context(), secret); return err }(),
				func() error { _, err := b.Store.ConsumeAuthCode(t.Context(), secret, "fam", t0); return err }(),
				func() error { _, err := b.Store.ConsumeRefresh(t.Context(), secret, "ui", t0); return err }(),
				func() error { _, err := b.Store.LookupBrowserSession(t.Context(), secret); return err }(),
				func() error { _, err := b.Store.LookupDeviceCodeByDeviceCode(t.Context(), secret); return err }(),
				func() error { _, err := b.Store.PollDeviceCode(t.Context(), secret, t0); return err }(),
				func() error { _, err := b.Store.ConsumeDeviceCode(t.Context(), secret); return err }(),
			} {
				require.Error(t, err)
				require.NotContains(t, err.Error(), secret)
			}
		}},
	}
}
