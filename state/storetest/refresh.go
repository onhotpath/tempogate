package storetest

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/onhotpath/tempogate/admin"
	"github.com/onhotpath/tempogate/oidc"
)

// raceIterations is how many times the refresh-versus-revoke race runs: each
// iteration is cheap, and a backend with write skew loses it only sometimes.
const raceIterations = 50

func refresh(token, family string) oidc.Refresh {
	return oidc.Refresh{
		Token:     token,
		JTI:       "jti-" + token,
		ClientID:  "ui",
		Subject:   "sub-alice",
		Email:     "alice@example.com",
		FamilyID:  family,
		AuthTime:  t0,
		CreatedAt: t0,
		ExpiresAt: t0.Add(24 * time.Hour),
	}
}

func saveRefresh(t *testing.T, s Store, rs ...oidc.Refresh) {
	t.Helper()
	for _, r := range rs {
		require.NoError(t, s.SaveRefresh(t.Context(), r))
	}
}

func requireRefresh(t *testing.T, want, got oidc.Refresh) {
	t.Helper()
	requireTime(t, want.AuthTime, got.AuthTime, "refresh auth_time")
	requireTime(t, want.CreatedAt, got.CreatedAt, "refresh created_at")
	requireTime(t, want.ExpiresAt, got.ExpiresAt, "refresh expires_at")
	got.AuthTime, got.CreatedAt, got.ExpiresAt = want.AuthTime, want.CreatedAt, want.ExpiresAt
	require.Equal(t, want, got)
}

// requireNotLive fails when token can still be exchanged by client.
func requireNotLive(t *testing.T, s Store, token, client string) {
	t.Helper()
	_, err := s.ConsumeRefresh(t.Context(), token, client, t0)
	requireOneOf(t, err, oidc.ErrRefreshNotFound, oidc.ErrRefreshReused)
}

func refreshCases() []testCase {
	return []testCase{
		{"Refresh/ConsumeRotatesOnceAndLeavesATombstone", func(t *testing.T, b Backend) {
			want := refresh("rt-1", "fam")
			saveRefresh(t, b.Store, want)

			got, err := b.Store.ConsumeRefresh(t.Context(), want.Token, want.ClientID, t0.Add(time.Minute))
			require.NoError(t, err)
			requireRefresh(t, want, got)

			replay, err := b.Store.ConsumeRefresh(t.Context(), want.Token, want.ClientID, t0.Add(2*time.Minute))
			require.ErrorIs(t, err, oidc.ErrRefreshReused)
			requireRefresh(t, want, replay)
		}},
		{"Refresh/ConsumeUnknown", func(t *testing.T, b Backend) {
			_, err := b.Store.ConsumeRefresh(t.Context(), "never-issued", "ui", t0)
			require.ErrorIs(t, err, oidc.ErrRefreshNotFound)
		}},
		{"Refresh/AnotherClientCannotBurnOrProbeTheToken", func(t *testing.T, b Backend) {
			r := refresh("rt-1", "fam")
			saveRefresh(t, b.Store, r)

			_, err := b.Store.ConsumeRefresh(t.Context(), r.Token, "someone-else", t0)
			require.ErrorIs(t, err, oidc.ErrRefreshNotFound)
			_, err = b.Store.ConsumeRefresh(t.Context(), r.Token, r.ClientID, t0)
			require.NoError(t, err, "the owner's token is still live")

			_, err = b.Store.ConsumeRefresh(t.Context(), r.Token, "someone-else", t0)
			require.ErrorIs(t, err, oidc.ErrRefreshNotFound, "another client does not learn of the tombstone")
		}},
		{"Refresh/DuplicateTokenFailsAndKeepsTheOriginal", func(t *testing.T, b Backend) {
			first := refresh("rt-1", "fam")
			saveRefresh(t, b.Store, first)
			dup := refresh("rt-1", "fam-other")
			require.Error(t, b.Store.SaveRefresh(t.Context(), dup))

			got, err := b.Store.ConsumeRefresh(t.Context(), "rt-1", "ui", t0)
			require.NoError(t, err)
			require.Equal(t, first.FamilyID, got.FamilyID)
		}},
		{"Refresh/ConcurrentConsumesHaveOneWinner", func(t *testing.T, b Backend) {
			saveRefresh(t, b.Store, refresh("hot", "fam"))
			errs := race(func(int) error {
				_, err := b.Store.ConsumeRefresh(t.Context(), "hot", "ui", t0)
				return err
			})
			require.Equal(t, 1, winners(errs), "%v", errs)
			for _, err := range errs {
				if err != nil {
					require.ErrorIs(t, err, oidc.ErrRefreshReused)
				}
			}
		}},
		{"Refresh/RevokeFamilyEndsTheChainButKeepsTombstones", func(t *testing.T, b Backend) {
			saveRefresh(t, b.Store, refresh("a1", "fam-a"), refresh("a2", "fam-a"), refresh("b1", "fam-b"))
			_, err := b.Store.ConsumeRefresh(t.Context(), "a1", "ui", t0)
			require.NoError(t, err)

			n, err := b.Store.RevokeRefreshFamily(t.Context(), "fam-a", t0.Add(time.Minute))
			require.NoError(t, err)
			require.Equal(t, 1, n, "only live tokens are counted")

			_, err = b.Store.ConsumeRefresh(t.Context(), "a2", "ui", t0)
			require.ErrorIs(t, err, oidc.ErrRefreshNotFound, "a revoked live token is gone")
			_, err = b.Store.ConsumeRefresh(t.Context(), "a1", "ui", t0)
			require.ErrorIs(t, err, oidc.ErrRefreshReused, "a revoked tombstone is still recognised as reuse")
			_, err = b.Store.ConsumeRefresh(t.Context(), "b1", "ui", t0)
			require.NoError(t, err, "other families are untouched")

			n, err = b.Store.RevokeRefreshFamily(t.Context(), "fam-a", t0.Add(2*time.Minute))
			require.NoError(t, err)
			require.Zero(t, n, "revoking a revoked family is a no-op")

			require.ErrorIs(t, b.Store.SaveRefresh(t.Context(), refresh("a3", "fam-a")), oidc.ErrRefreshFamilyRevoked)
			requireNotLive(t, b.Store, "a3", "ui")
		}},
		{"Refresh/RotationRacingRevocationLeavesNoLiveChild", func(t *testing.T, b Backend) {
			// The guarantee the refresh_families row lock provides under
			// READ COMMITTED: whatever the interleaving, a family that was
			// revoked has no live token afterwards. Either the rotation's
			// child is refused (ErrRefreshFamilyRevoked), or it is saved
			// first and then revoked with the rest of the family.
			for i := range raceIterations {
				fam := fmt.Sprintf("fam-%02d", i)
				parent, child := refresh("p-"+fam, fam), refresh("c-"+fam, fam)
				saveRefresh(t, b.Store, parent)

				var (
					wg          sync.WaitGroup
					start       = make(chan struct{})
					rotateErr   error
					revokeErr   error
					rotatedLive bool
				)
				wg.Add(2)
				go func() {
					defer wg.Done()
					<-start
					if _, err := b.Store.ConsumeRefresh(t.Context(), parent.Token, parent.ClientID, t0); err != nil {
						return // revoked first: nothing to rotate
					}
					rotateErr = b.Store.SaveRefresh(t.Context(), child)
					rotatedLive = rotateErr == nil
				}()
				go func() {
					defer wg.Done()
					<-start
					_, revokeErr = b.Store.RevokeRefreshFamily(t.Context(), fam, t0)
				}()
				close(start)
				wg.Wait()

				require.NoError(t, revokeErr)
				if rotateErr != nil {
					require.ErrorIs(t, rotateErr, oidc.ErrRefreshFamilyRevoked)
				}
				_, err := b.Store.ConsumeRefresh(t.Context(), child.Token, child.ClientID, t0)
				require.ErrorIsf(t, err, oidc.ErrRefreshNotFound,
					"iteration %d: a live child survived its family's revocation (saved=%v)", i, rotatedLive)
			}
		}},
	}
}

func sessionCases() []testCase {
	// alice signed in twice and rotated once in the first family; bob once;
	// carol's family was revoked; dave's token expired; erin's was consumed
	// without a successor (a reuse revoked it upstream of the store).
	seed := func(t *testing.T, b Backend) {
		t.Helper()
		person := func(token, family, email, subject string, authTime time.Time) oidc.Refresh {
			r := refresh(token, family)
			r.Email, r.Subject, r.AuthTime, r.CreatedAt = email, subject, authTime, authTime
			return r
		}
		alice1 := person("alice-1", "fam-alice-1", "alice@example.com", "sub-alice", t0)
		alice1b := person("alice-1b", "fam-alice-1", "alice@example.com", "sub-alice", t0)
		alice1b.CreatedAt = t0.Add(time.Hour)
		saveRefresh(t, b.Store,
			alice1,
			alice1b,
			person("alice-2", "fam-alice-2", "alice@example.com", "sub-alice", t0.Add(time.Minute)),
			person("bob-1", "fam-bob", "bob@example.com", "sub-bob", t0),
			person("carol-1", "fam-carol", "carol@example.com", "sub-carol", t0),
			person("erin-1", "fam-erin", "erin@example.com", "sub-erin", t0),
		)
		dave := person("dave-1", "fam-dave", "dave@example.com", "sub-dave", t0)
		dave.ExpiresAt = t0.Add(time.Minute)
		saveRefresh(t, b.Store, dave)

		_, err := b.Store.ConsumeRefresh(t.Context(), "alice-1", "ui", t0.Add(time.Hour))
		require.NoError(t, err)
		_, err = b.Store.ConsumeRefresh(t.Context(), "erin-1", "ui", t0)
		require.NoError(t, err)
		_, err = b.Sessions.RevokeFamily(t.Context(), "fam-carol", t0)
		require.NoError(t, err)
	}
	families := func(ss []admin.Session) []string {
		out := make([]string, 0, len(ss))
		for _, s := range ss {
			out = append(out, s.FamilyID)
		}
		return out
	}
	now := t0.Add(2 * time.Hour)

	return []testCase{
		{"Sessions/ListShowsOneLiveTokenPerFamilyInOrder", func(t *testing.T, b Backend) {
			seed(t, b)
			got, err := b.Sessions.List(t.Context(), admin.SessionFilter{}, now)
			require.NoError(t, err)
			require.Equal(t, []string{"fam-alice-1", "fam-alice-2", "fam-bob"}, families(got),
				"ordered by email then auth_time; revoked, expired and consumed-only families are not sessions")

			first := got[0]
			require.Equal(t, "ui", first.ClientID)
			require.Equal(t, "sub-alice", first.Subject)
			require.Equal(t, "alice@example.com", first.Email)
			requireTime(t, t0, first.AuthTime, "session auth_time")
			requireTime(t, t0.Add(time.Hour), first.RotatedAt, "session rotated_at (the live token's created_at)")
			requireTime(t, t0.Add(24*time.Hour), first.ExpiresAt, "session expires_at")
		}},
		{"Sessions/ListJudgesExpiryAtTheCallersNow", func(t *testing.T, b Backend) {
			seed(t, b)
			got, err := b.Sessions.List(t.Context(), admin.SessionFilter{Email: "dave@example.com"}, t0)
			require.NoError(t, err)
			require.Equal(t, []string{"fam-dave"}, families(got))

			got, err = b.Sessions.List(t.Context(), admin.SessionFilter{Email: "dave@example.com"}, t0.Add(time.Minute))
			require.NoError(t, err)
			require.Empty(t, got, "a token is expired from its expires_at on")
		}},
		{"Sessions/ListFiltersEmailCaseInsensitivelyAndSubjectExactly", func(t *testing.T, b Backend) {
			seed(t, b)
			got, err := b.Sessions.List(t.Context(), admin.SessionFilter{Email: "ALICE@Example.com"}, now)
			require.NoError(t, err)
			require.Equal(t, []string{"fam-alice-1", "fam-alice-2"}, families(got))

			got, err = b.Sessions.List(t.Context(), admin.SessionFilter{Subject: "sub-bob"}, now)
			require.NoError(t, err)
			require.Equal(t, []string{"fam-bob"}, families(got))

			got, err = b.Sessions.List(t.Context(), admin.SessionFilter{Subject: "SUB-BOB"}, now)
			require.NoError(t, err)
			require.Empty(t, got)

			got, err = b.Sessions.List(t.Context(), admin.SessionFilter{Email: "alice@example.com", Subject: "sub-bob"}, now)
			require.NoError(t, err)
			require.Empty(t, got, "filters combine")
		}},
		{"Sessions/RevokeFamily", func(t *testing.T, b Backend) {
			seed(t, b)
			n, err := b.Sessions.RevokeFamily(t.Context(), "fam-alice-1", now)
			require.NoError(t, err)
			require.Equal(t, 1, n)
			requireNotLive(t, b.Store, "alice-1b", "ui")

			n, err = b.Sessions.RevokeFamily(t.Context(), "fam-alice-1", now)
			require.NoError(t, err)
			require.Zero(t, n)

			_, err = b.Sessions.RevokeFamily(t.Context(), "fam-never-issued", now)
			require.ErrorIs(t, err, admin.ErrSessionNotFound)
		}},
		{"Sessions/RevokeEmailIsCaseInsensitive", func(t *testing.T, b Backend) {
			seed(t, b)
			n, err := b.Sessions.RevokeEmail(t.Context(), "Alice@EXAMPLE.com", now)
			require.NoError(t, err)
			require.Equal(t, 2, n)
			requireNotLive(t, b.Store, "alice-1b", "ui")
			requireNotLive(t, b.Store, "alice-2", "ui")

			n, err = b.Sessions.RevokeEmail(t.Context(), "nobody@example.com", now)
			require.NoError(t, err)
			require.Zero(t, n)
			_, err = b.Store.ConsumeRefresh(t.Context(), "bob-1", "ui", now)
			require.NoError(t, err)
		}},
		{"Sessions/RevokeSubjectIsExact", func(t *testing.T, b Backend) {
			seed(t, b)
			n, err := b.Sessions.RevokeSubject(t.Context(), "SUB-ALICE", now)
			require.NoError(t, err)
			require.Zero(t, n)

			n, err = b.Sessions.RevokeSubject(t.Context(), "sub-alice", now)
			require.NoError(t, err)
			require.Equal(t, 2, n)
			got, err := b.Sessions.List(t.Context(), admin.SessionFilter{}, now)
			require.NoError(t, err)
			require.Equal(t, []string{"fam-bob"}, families(got))
		}},
	}
}
