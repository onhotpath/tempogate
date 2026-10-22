package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/onhotpath/tempogate/keys"
)

func awaitChange(t *testing.T, ch <-chan keys.Change, want keys.Change) {
	t.Helper()
	timeout := time.After(10 * time.Second)
	for {
		select {
		case c := <-ch:
			if c == want {
				return
			}
		case <-timeout:
			t.Fatalf("no %+v within 10s", want)
		}
	}
}

func TestChangeEncoding(t *testing.T) {
	for _, c := range []keys.Change{{Kind: keys.ChangeKeys}, {Kind: keys.ChangeJTIRevoked, JTI: "0192-abc"}} {
		got, ok := decodeChange(encodeChange(c))
		require.True(t, ok)
		require.Equal(t, c, got)
	}
	for _, payload := range []string{"", "jti:", "nonsense"} {
		_, ok := decodeChange(payload)
		require.Falsef(t, ok, "%q is ignored", payload)
	}
}

func TestChangeFeed(t *testing.T) {
	forEachServer(t, func(t *testing.T, srv testServer) {
		// Replicas share one database: a write through one store reaches
		// the subscribers of another.
		t.Run("AnotherReplicasWritesAreReported", func(t *testing.T) {
			dsn := newDatabase(t, srv)
			a, b := newStoreOn(t, dsn), newStoreOn(t, dsn)
			require.NoError(t, a.Migrate(t.Context()))

			ch := a.SubscribeChanges(t.Context())
			k := saveKey(t, b, nil)
			_, err := b.MarkIntegrationKeyRevoked(t.Context(), k.ID, reapNow)
			require.NoError(t, err)
			awaitChange(t, ch, keys.Change{Kind: keys.ChangeJTIRevoked, JTI: k.JTI})
		})

		// NOTIFY is not queued for a listener that is away, so after a
		// reconnect the feed reports what it may have missed.
		t.Run("ReconnectsAndResyncs", func(t *testing.T) {
			core, logs := observer.New(zapcore.WarnLevel)
			s := newTestStore(t, srv, WithLogger(zap.New(core)))
			ch := s.SubscribeChanges(t.Context())
			awaitChange(t, ch, keys.Change{Kind: keys.ChangeKeys}) // the first connect's resync

			// Denylisted without a notification, as if its NOTIFY had been
			// sent while the listener was away.
			_, err := s.pool.Exec(t.Context(), `INSERT INTO jti_denylist (jti, revoked_at) VALUES ('missed', $1)`, time.Now().UTC())
			require.NoError(t, err)

			var killed int
			require.NoError(t, s.pool.QueryRow(t.Context(),
				`SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity
				 WHERE application_name = $1 AND datname = current_database()`, feedApplicationName).Scan(&killed))
			require.Equal(t, 1, killed, "the store holds one LISTEN connection")

			awaitChange(t, ch, keys.Change{Kind: keys.ChangeJTIRevoked, JTI: "missed"})
			require.NotZero(t, logs.FilterMessageSnippet("change feed connection lost").Len())

			k := saveKey(t, s, nil)
			_, err = s.MarkIntegrationKeyRevoked(t.Context(), k.ID, reapNow)
			require.NoError(t, err)
			awaitChange(t, ch, keys.Change{Kind: keys.ChangeJTIRevoked, JTI: k.JTI})
		})

		t.Run("AnUnreachableListenerDoesNotHoldSubscribers", func(t *testing.T) {
			core, logs := observer.New(zapcore.WarnLevel)
			s := newTestStore(t, srv, WithListenDSN("postgres://nobody@127.0.0.1:1/x?connect_timeout=1"), WithLogger(zap.New(core)))
			ch := s.SubscribeChanges(t.Context())
			require.NotNil(t, ch)
			require.Eventually(t, func() bool { return logs.FilterMessageSnippet("change feed connection lost").Len() > 0 },
				10*time.Second, 10*time.Millisecond)
			require.NoError(t, s.Close())
		})

		t.Run("ASubscriptionWhoseContextIsDoneReturns", func(t *testing.T) {
			s := newTestStore(t, srv, WithListenDSN("postgres://nobody@127.0.0.1:1/x?connect_timeout=5"))
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			ch := s.SubscribeChanges(ctx)
			require.Eventually(t, func() bool {
				_, ok := <-ch
				return !ok
			}, 5*time.Second, 10*time.Millisecond)
		})
	})

	t.Run("CloseWithoutAFeed", func(t *testing.T) {
		s, err := New(WithDSN("postgres://localhost/x"))
		require.NoError(t, err)
		require.NoError(t, s.Close())
		ch := s.SubscribeChanges(t.Context())
		require.NotNil(t, ch, "subscribing after Close neither blocks nor panics")
	})
}
