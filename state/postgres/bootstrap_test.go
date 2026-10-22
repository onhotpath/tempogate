package postgres

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/onhotpath/tempogate/keys"
)

// TestReplicasBootingTogetherGenerateOneKey: every replica runs keys.Init
// at start; on an empty database the bootstrap lock makes the first one
// generate the signing key and the others load it, instead of each
// generating and signing with its own.
func TestReplicasBootingTogetherGenerateOneKey(t *testing.T) {
	forEachServer(t, func(t *testing.T, srv testServer) {
		dsn := newDatabase(t, srv)
		const replicas = 4
		stores := make([]*Store, replicas)
		for i := range stores {
			stores[i] = newStoreOn(t, dsn)
		}
		require.NoError(t, stores[0].Migrate(t.Context()))

		signing := make([]string, replicas)
		var wg sync.WaitGroup
		for i, s := range stores {
			wg.Go(func() {
				k := keys.New(keys.WithStore(s), keys.WithBootstrapLocker(s), keys.WithPublishDelay(0),
					keys.WithGenerateOptions(keys.WithRSABits(2048)))
				require.NoError(t, k.Init(t.Context()))
				kp, ok := k.Signing(k.All())
				require.True(t, ok)
				signing[i] = kp.Kid
			})
		}
		wg.Wait()

		stored, err := stores[0].LoadKeypairs(t.Context())
		require.NoError(t, err)
		require.Len(t, stored, 1, "one key between all replicas")
		for _, kid := range signing {
			require.Equal(t, stored[0].Kid, kid, "every replica signs with it")
		}
	})
}
