package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/onhotpath/tempogate/keys"
	"github.com/onhotpath/tempogate/oidc"
	"github.com/onhotpath/tempogate/state/internal/secret"
)

// The conformance suite races these paths and catches a missing lock only
// sometimes. These cases force the interleaving instead: another
// transaction (standing in for a second replica) holds the lock half way
// through its own write, and the store call under test must wait for it
// and then see its result.

// holding runs setup in a transaction left open, then calls fn in the
// background, checks fn waits, commits, and returns fn's result.
func holding[T any](t *testing.T, s *Store, setup func(tx pgx.Tx), fn func() T) T {
	t.Helper()
	tx, err := s.pool.Begin(t.Context())
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(context.WithoutCancel(t.Context())) }()
	setup(tx)

	done := make(chan T, 1)
	go func() { done <- fn() }()
	select {
	case <-done:
		t.Fatal("did not wait for the other transaction's lock")
	case <-time.After(300 * time.Millisecond):
	}
	require.NoError(t, tx.Commit(t.Context()))
	select {
	case v := <-done:
		return v
	case <-time.After(10 * time.Second):
		t.Fatal("still waiting after the other transaction committed")
		panic("unreachable")
	}
}

func exec(t *testing.T, tx pgx.Tx, sql string, args ...any) {
	t.Helper()
	_, err := tx.Exec(t.Context(), sql, args...)
	require.NoError(t, err)
}

func TestLocks(t *testing.T) {
	forEachServer(t, func(t *testing.T, srv testServer) {
		at := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
		refresh := func(token string) oidc.Refresh {
			return oidc.Refresh{Token: token, ClientID: "ui", FamilyID: "fam", AuthTime: at, CreatedAt: at, ExpiresAt: at.Add(time.Hour)}
		}

		t.Run("RotationWaitsForAnInFlightRevocation", func(t *testing.T) {
			s := newTestStore(t, srv)
			require.NoError(t, s.SaveRefresh(t.Context(), refresh("parent")))
			err := holding(t, s,
				func(tx pgx.Tx) {
					exec(t, tx, `UPDATE refresh_families SET revoked_at = $1 WHERE family_id = 'fam'`, at)
				},
				func() error { return s.SaveRefresh(t.Context(), refresh("child")) },
			)
			require.ErrorIs(t, err, oidc.ErrRefreshFamilyRevoked)
		})

		t.Run("RevocationWaitsForAnInFlightRotation", func(t *testing.T) {
			s := newTestStore(t, srv)
			require.NoError(t, s.SaveRefresh(t.Context(), refresh("parent")))
			_, err := s.ConsumeRefresh(t.Context(), "parent", "ui", at)
			require.NoError(t, err)

			// A rotation that has locked the family and inserted its child,
			// but not yet committed.
			other := newStoreOn(t, s.pool.Config().ConnString())
			child := refresh("child")
			live := holding(t, s,
				func(tx pgx.Tx) {
					exec(t, tx, `SELECT 1 FROM refresh_families WHERE family_id = 'fam' FOR SHARE`)
					exec(t, tx, `INSERT INTO refresh_tokens (`+refreshColumns+`) VALUES ($1, '', 'ui', '', '', 'fam', $2, $2, $3)`,
						secret.Hash(child.Token), at, at.Add(time.Hour))
				},
				func() int {
					n, err := other.RevokeRefreshFamily(t.Context(), "fam", at)
					require.NoError(t, err)
					return n
				},
			)
			require.Equal(t, 1, live, "the child committed first and is revoked with its family")
			_, err = s.ConsumeRefresh(t.Context(), child.Token, "ui", at)
			require.ErrorIs(t, err, oidc.ErrRefreshNotFound)
		})

		t.Run("AnInFlightRotationHoldsOffRevocation", func(t *testing.T) {
			s := newTestStore(t, srv)
			require.NoError(t, s.SaveRefresh(t.Context(), refresh("parent")))
			_, err := s.ConsumeRefresh(t.Context(), "parent", "ui", at)
			require.NoError(t, err)

			// An uncommitted row with the child's hash stalls SaveRefresh's
			// INSERT after it has locked the family.
			stall, err := s.pool.Begin(t.Context())
			require.NoError(t, err)
			defer func() { _ = stall.Rollback(context.WithoutCancel(t.Context())) }()
			exec(t, stall, `INSERT INTO refresh_tokens (`+refreshColumns+`) VALUES ($1, '', 'ui', '', '', 'other', $2, $2, $2)`,
				secret.Hash("child"), at)

			saved := make(chan error, 1)
			go func() { saved <- s.SaveRefresh(t.Context(), refresh("child")) }()
			revoked := make(chan int, 1)
			time.Sleep(300 * time.Millisecond)
			go func() {
				n, err := s.RevokeRefreshFamily(t.Context(), "fam", at)
				assert.NoError(t, err)
				revoked <- n
			}()
			select {
			case <-revoked:
				t.Fatal("the revocation did not wait for the rotation holding its family")
			case <-time.After(300 * time.Millisecond):
			}

			require.NoError(t, stall.Rollback(t.Context()))
			require.NoError(t, <-saved)
			require.Equal(t, 1, <-revoked, "the child is revoked with its family")
			_, err = s.ConsumeRefresh(t.Context(), "child", "ui", at)
			require.ErrorIs(t, err, oidc.ErrRefreshNotFound)
		})

		t.Run("RetirementWaitsForAConcurrentOne", func(t *testing.T) {
			s := newTestStore(t, srv)
			for _, kid := range []string{"a", "b"} {
				require.NoError(t, s.SaveKeypair(t.Context(), keys.Keypair{Kid: kid, Alg: "RS256", PrivatePEM: []byte("p"), PublicPEM: []byte("p"), CreatedAt: at}))
			}
			err := holding(t, s,
				func(tx pgx.Tx) {
					exec(t, tx, `SELECT kid FROM keypairs WHERE retired_at IS NULL ORDER BY kid FOR UPDATE`)
					exec(t, tx, `UPDATE keypairs SET retired_at = $1 WHERE kid = 'a'`, at)
				},
				func() error { _, err := s.RetireKeypair(t.Context(), "b", at); return err },
			)
			require.ErrorIs(t, err, keys.ErrLastActiveKeypair)
		})

		t.Run("APollWaitsForAConcurrentOne", func(t *testing.T) {
			s := newTestStore(t, srv)
			require.NoError(t, s.SaveDeviceCode(t.Context(), oidc.DeviceCode{
				Code: "dc", UserCode: "ABCDEFGH", ClientID: "cli", Scope: "openid",
				IntervalSeconds: 5, CreatedAt: at, ExpiresAt: at.Add(time.Hour),
			}))
			slowDown := holding(t, s,
				func(tx pgx.Tx) {
					exec(t, tx, `SELECT 1 FROM device_codes WHERE user_code = 'ABCDEFGH' FOR UPDATE`)
					exec(t, tx, `UPDATE device_codes SET last_polled_at = $1 WHERE user_code = 'ABCDEFGH'`, at)
				},
				func() bool {
					slow, err := s.PollDeviceCode(t.Context(), "dc", at)
					require.NoError(t, err)
					return slow
				},
			)
			require.True(t, slowDown, "the poll judged against the other poll's stamp")
		})
	})
}
