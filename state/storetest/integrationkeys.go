package storetest

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/onhotpath/tempogate/admin"
)

func integrationKey(id, owner, namespace string) admin.IntegrationKey {
	exp := t0.Add(24 * time.Hour)
	return admin.IntegrationKey{
		ID:        id,
		Namespace: namespace,
		Role:      admin.RoleWorker,
		Owner:     owner,
		JTI:       "jti-" + id,
		CreatedAt: t0,
		ExpiresAt: &exp,
	}
}

func saveKeys(t *testing.T, r admin.KeyRegistry, ks ...admin.IntegrationKey) {
	t.Helper()
	for _, k := range ks {
		require.NoError(t, r.Save(t.Context(), k))
	}
}

func ids(ks []admin.IntegrationKey) []string {
	out := make([]string, 0, len(ks))
	for _, k := range ks {
		out = append(out, k.ID)
	}
	return out
}

func integrationKeyCases() []testCase {
	return []testCase{
		{"KeyRegistry/SaveAndByIDRoundTrip", func(t *testing.T, b Backend) {
			want := integrationKey("key-1", "svc", "payments")
			noExpiry := integrationKey("key-2", "svc", "payments")
			noExpiry.ExpiresAt = nil
			saveKeys(t, b.KeyRegistry, want, noExpiry)

			got, err := b.KeyRegistry.ByID(t.Context(), want.ID)
			require.NoError(t, err)
			requireTime(t, want.CreatedAt, got.CreatedAt, "key created_at")
			requireTimePtr(t, *want.ExpiresAt, got.ExpiresAt, "key expires_at")
			got.CreatedAt, got.ExpiresAt = want.CreatedAt, want.ExpiresAt
			require.Equal(t, want, got)

			got, err = b.KeyRegistry.ByID(t.Context(), noExpiry.ID)
			require.NoError(t, err)
			require.Nil(t, got.ExpiresAt)
			require.Nil(t, got.RevokedAt)
		}},
		{"KeyRegistry/ByIDUnknown", func(t *testing.T, b Backend) {
			_, err := b.KeyRegistry.ByID(t.Context(), "never-minted")
			require.ErrorIs(t, err, admin.ErrIntegrationKeyNotFound)
		}},
		{"KeyRegistry/DuplicateIDOrJTIFails", func(t *testing.T, b Backend) {
			saveKeys(t, b.KeyRegistry, integrationKey("key-1", "svc", "payments"))
			sameID := integrationKey("key-1", "other", "payments")
			sameID.JTI = "jti-other"
			require.Error(t, b.KeyRegistry.Save(t.Context(), sameID))
			sameJTI := integrationKey("key-2", "svc", "payments")
			sameJTI.JTI = "jti-key-1"
			require.Error(t, b.KeyRegistry.Save(t.Context(), sameJTI))
		}},
		{"KeyRegistry/ListOrdersByIDDescendingFiltersAndPages", func(t *testing.T, b Backend) {
			saveKeys(t, b.KeyRegistry,
				integrationKey("key-03", "svc-a", "payments"),
				integrationKey("key-01", "svc-a", "payments"),
				integrationKey("key-05", "svc-b", "payments"),
				integrationKey("key-02", "svc-b", "billing"),
				integrationKey("key-04", "svc-a", "billing"),
			)
			list := func(f admin.ListFilter) []string {
				t.Helper()
				got, err := b.KeyRegistry.List(t.Context(), f)
				require.NoError(t, err)
				return ids(got)
			}
			require.Equal(t, []string{"key-05", "key-04", "key-03"}, list(admin.ListFilter{Limit: 2}),
				"limit+1 rows, so the caller can tell there is more")
			require.Equal(t, []string{"key-03", "key-02", "key-01"}, list(admin.ListFilter{Limit: 2, Cursor: "key-04"}),
				"the cursor is exclusive")
			require.Equal(t, []string{"key-04", "key-03", "key-01"}, list(admin.ListFilter{Limit: 10, Owner: "svc-a"}))
			require.Equal(t, []string{"key-04", "key-02"}, list(admin.ListFilter{Limit: 10, Namespace: "billing"}))
			require.Equal(t, []string{"key-04"}, list(admin.ListFilter{Limit: 10, Owner: "svc-a", Namespace: "billing"}))
		}},
		{"KeyRegistry/ListDefaultsANonPositiveLimit", func(t *testing.T, b Backend) {
			const defaultLimit = 50
			for i := range defaultLimit + 5 {
				saveKeys(t, b.KeyRegistry, integrationKey(fmt.Sprintf("key-%03d", i), "svc", "payments"))
			}
			for _, limit := range []int{0, -1} {
				got, err := b.KeyRegistry.List(t.Context(), admin.ListFilter{Limit: limit})
				require.NoError(t, err)
				require.Len(t, got, defaultLimit+1)
			}
		}},
		{"KeyRegistry/MarkRevokedDenylistsTheJTIWithTheCallersTime", func(t *testing.T, b Backend) {
			k := integrationKey("key-1", "svc", "payments")
			saveKeys(t, b.KeyRegistry, k)
			revoked, err := b.Store.IsRevoked(t.Context(), k.JTI)
			require.NoError(t, err)
			require.False(t, revoked)

			at := t0.Add(time.Hour)
			jti, err := b.KeyRegistry.MarkRevoked(t.Context(), k.ID, at)
			require.NoError(t, err)
			require.Equal(t, k.JTI, jti)

			got, err := b.KeyRegistry.ByID(t.Context(), k.ID)
			require.NoError(t, err)
			requireTimePtr(t, at, got.RevokedAt, "revoked_at")
			revoked, err = b.Store.IsRevoked(t.Context(), k.JTI)
			require.NoError(t, err)
			require.True(t, revoked)
		}},
		{"KeyRegistry/MarkRevokedIsIdempotent", func(t *testing.T, b Backend) {
			k := integrationKey("key-1", "svc", "payments")
			saveKeys(t, b.KeyRegistry, k)
			first := t0.Add(time.Hour)
			_, err := b.KeyRegistry.MarkRevoked(t.Context(), k.ID, first)
			require.NoError(t, err)

			jti, err := b.KeyRegistry.MarkRevoked(t.Context(), k.ID, first.Add(time.Hour))
			require.NoError(t, err)
			require.Equal(t, k.JTI, jti)
			got, err := b.KeyRegistry.ByID(t.Context(), k.ID)
			require.NoError(t, err)
			requireTimePtr(t, first, got.RevokedAt, "revoked_at after a second revoke")
		}},
		{"KeyRegistry/MarkRevokedUnknown", func(t *testing.T, b Backend) {
			_, err := b.KeyRegistry.MarkRevoked(t.Context(), "never-minted", t0)
			require.ErrorIs(t, err, admin.ErrIntegrationKeyNotFound)
		}},
	}
}
