package storetest

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/onhotpath/tempogate/keys"
)

func keypair(kid string, created time.Time) keys.Keypair {
	return keys.Keypair{
		Kid: kid,
		Alg: keys.AlgRS256,
		// Opaque bytes, not text: a sealed private key (KEYS_ENCRYPTION_KEY)
		// is arbitrary binary, NULs included.
		PrivatePEM: []byte("private-" + kid + "\x00\xff"),
		PublicPEM:  []byte("public-" + kid),
		CreatedAt:  created,
	}
}

func saveKeypairs(t *testing.T, s Store, kps ...keys.Keypair) {
	t.Helper()
	for _, kp := range kps {
		require.NoError(t, s.SaveKeypair(t.Context(), kp))
	}
}

func loadKids(t *testing.T, s Store) []string {
	t.Helper()
	kps, err := s.LoadKeypairs(t.Context())
	require.NoError(t, err)
	kids := make([]string, 0, len(kps))
	for _, kp := range kps {
		kids = append(kids, kp.Kid)
	}
	return kids
}

func keyCases() []testCase {
	return []testCase{
		{"KeyStore/LoadEmptyStore", func(t *testing.T, b Backend) {
			kps, err := b.Store.LoadKeypairs(t.Context())
			require.NoError(t, err)
			require.Empty(t, kps)
		}},
		{"KeyStore/SaveLoadRoundTrip", func(t *testing.T, b Backend) {
			want := keypair("kid-1", t0)
			saveKeypairs(t, b.Store, want)

			got, err := b.Store.LoadKeypairs(t.Context())
			require.NoError(t, err)
			require.Len(t, got, 1)
			require.Equal(t, want.Kid, got[0].Kid)
			require.Equal(t, want.Alg, got[0].Alg)
			require.Equal(t, want.PrivatePEM, got[0].PrivatePEM)
			require.Equal(t, want.PublicPEM, got[0].PublicPEM)
			requireTime(t, want.CreatedAt, got[0].CreatedAt, "created_at")
			require.Nil(t, got[0].RetiredAt)
		}},
		{"KeyStore/DuplicateKidFailsAndKeepsTheOriginal", func(t *testing.T, b Backend) {
			first := keypair("kid-1", t0)
			saveKeypairs(t, b.Store, first)

			dup := keypair("kid-1", t0.Add(time.Hour))
			dup.PrivatePEM = []byte("other")
			require.Error(t, b.Store.SaveKeypair(t.Context(), dup))

			got, err := b.Store.LoadKeypairs(t.Context())
			require.NoError(t, err)
			require.Len(t, got, 1)
			require.Equal(t, first.PrivatePEM, got[0].PrivatePEM)
		}},
		{"KeyStore/LoadOrdersByCreatedAtThenKid", func(t *testing.T, b Backend) {
			// Inserted out of order, one microsecond apart and with a tie,
			// so neither insertion order nor second precision can pass.
			saveKeypairs(t, b.Store,
				keypair("kid-c", t0.Add(2*time.Microsecond)),
				keypair("kid-b", t0),
				keypair("kid-d", t0.Add(time.Microsecond)),
				keypair("kid-a", t0),
			)
			require.Equal(t, []string{"kid-a", "kid-b", "kid-d", "kid-c"}, loadKids(t, b.Store))
		}},
		{"KeyStore/RetireStampsOnceAndKeepsTheFirstRetirement", func(t *testing.T, b Backend) {
			saveKeypairs(t, b.Store, keypair("old", t0), keypair("new", t0.Add(time.Minute)))

			at := t0.Add(time.Hour)
			kp, err := b.Store.RetireKeypair(t.Context(), "old", at)
			require.NoError(t, err)
			require.NotNil(t, kp.RetiredAt)
			requireTime(t, at, *kp.RetiredAt, "retired_at")

			again, err := b.Store.RetireKeypair(t.Context(), "old", at.Add(time.Hour))
			require.NoError(t, err, "retiring a retired keypair returns it unchanged")
			require.NotNil(t, again.RetiredAt)
			requireTime(t, at, *again.RetiredAt, "retired_at after a second retire")

			got, err := b.Store.LoadKeypairs(t.Context())
			require.NoError(t, err)
			require.Len(t, got, 2)
			require.NotNil(t, got[0].RetiredAt)
			require.Nil(t, got[1].RetiredAt)
		}},
		{"KeyStore/RetireUnknownKid", func(t *testing.T, b Backend) {
			saveKeypairs(t, b.Store, keypair("kid-1", t0))
			_, err := b.Store.RetireKeypair(t.Context(), "nope", t0)
			require.ErrorIs(t, err, keys.ErrKeypairNotFound)
		}},
		{"KeyStore/RetireRefusesTheLastActiveKeypair", func(t *testing.T, b Backend) {
			saveKeypairs(t, b.Store, keypair("kid-1", t0))
			_, err := b.Store.RetireKeypair(t.Context(), "kid-1", t0)
			require.ErrorIs(t, err, keys.ErrLastActiveKeypair)

			got, err := b.Store.LoadKeypairs(t.Context())
			require.NoError(t, err)
			require.Nil(t, got[0].RetiredAt)
		}},
		{"KeyStore/ConcurrentRetiresLeaveOneActive", func(t *testing.T, b Backend) {
			for i := range racers {
				saveKeypairs(t, b.Store, keypair(fmt.Sprintf("kid-%02d", i), t0.Add(time.Duration(i)*time.Second)))
			}
			errs := race(func(i int) error {
				_, err := b.Store.RetireKeypair(t.Context(), fmt.Sprintf("kid-%02d", i), t0.Add(time.Hour))
				return err
			})
			require.Equal(t, racers-1, winners(errs), "all but one retirement succeed: %v", errs)
			for _, err := range errs {
				if err != nil {
					require.ErrorIs(t, err, keys.ErrLastActiveKeypair)
				}
			}

			kps, err := b.Store.LoadKeypairs(t.Context())
			require.NoError(t, err)
			active := 0
			for _, kp := range kps {
				if !kp.Retired() {
					active++
				}
			}
			require.Equal(t, 1, active)
		}},
		{"PrivateKeyRewriter/RewritesOneKeypairInPlace", func(t *testing.T, b Backend) {
			saveKeypairs(t, b.Store, keypair("kid-1", t0), keypair("kid-2", t0.Add(time.Second)))

			sealed := []byte("sealed\x00\x01")
			require.NoError(t, b.Store.UpdateKeypairPrivatePEM(t.Context(), "kid-1", sealed))

			got, err := b.Store.LoadKeypairs(t.Context())
			require.NoError(t, err)
			require.Equal(t, sealed, got[0].PrivatePEM)
			require.Equal(t, keypair("kid-2", t0).PrivatePEM, got[1].PrivatePEM)
			require.Equal(t, keypair("kid-1", t0).PublicPEM, got[0].PublicPEM)

			require.Error(t, b.Store.UpdateKeypairPrivatePEM(t.Context(), "nope", sealed))
		}},
		{"DenylistChecker/UnknownJTIIsNotRevoked", func(t *testing.T, b Backend) {
			revoked, err := b.Store.IsRevoked(t.Context(), "never-revoked")
			require.NoError(t, err)
			require.False(t, revoked)
		}},
	}
}

// requireTime fails unless got is the instant want, to the microsecond: a
// backend may drop precision below a microsecond, never above it.
func requireTime(t *testing.T, want, got time.Time, what string) {
	t.Helper()
	if got.Equal(want) || got.Equal(want.Truncate(time.Microsecond)) {
		return
	}
	t.Fatalf("%s = %v, want %v (to the microsecond)", what, got, want)
}

// requireOneOf fails unless err matches one of targets.
func requireOneOf(t *testing.T, err error, targets ...error) {
	t.Helper()
	for _, target := range targets {
		if errors.Is(err, target) {
			return
		}
	}
	t.Fatalf("error %v, want one of %v", err, targets)
}
