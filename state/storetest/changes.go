package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/onhotpath/tempogate/keys"
)

// changeWait bounds how long a case waits for a change. Delivery is
// best-effort but, with nothing dropped, prompt.
const changeWait = 5 * time.Second

// awaitChange returns the first change on ch that match accepts, skipping
// others: a feed may report spurious or duplicate changes.
func awaitChange(t *testing.T, ch <-chan keys.Change, match func(keys.Change) bool) keys.Change {
	t.Helper()
	timeout := time.After(changeWait)
	for {
		select {
		case c, ok := <-ch:
			require.True(t, ok, "change feed closed while its context was live")
			if match(c) {
				return c
			}
		case <-timeout:
			t.Fatalf("no matching change within %s", changeWait)
		}
	}
}

func isKeys(c keys.Change) bool { return c.Kind == keys.ChangeKeys }

func changeCases() []testCase {
	feed := func(t *testing.T, b Backend) keys.ChangeFeed {
		t.Helper()
		if b.Changes == nil {
			t.Skip("backend has no change feed; consumers rely on periodic reload alone")
		}
		return b.Changes
	}
	return []testCase{
		{"Changes/KeyWritesAreReported", func(t *testing.T, b Backend) {
			ch := feed(t, b).SubscribeChanges(t.Context())

			saveKeypairs(t, b.Store, keypair("kid-1", t0))
			awaitChange(t, ch, isKeys)
			saveKeypairs(t, b.Store, keypair("kid-2", t0.Add(time.Second)))
			awaitChange(t, ch, isKeys)

			_, err := b.Store.RetireKeypair(t.Context(), "kid-1", t0)
			require.NoError(t, err)
			awaitChange(t, ch, isKeys)

			require.NoError(t, b.Store.UpdateKeypairPrivatePEM(t.Context(), "kid-2", []byte("sealed")))
			awaitChange(t, ch, isKeys)
		}},
		{"Changes/RevocationIsReportedAfterItCommits", func(t *testing.T, b Backend) {
			ch := feed(t, b).SubscribeChanges(t.Context())
			k := integrationKey("key-1", "svc", "payments")
			saveKeys(t, b.KeyRegistry, k)

			// Revoke concurrently, so the check on receipt proves the change
			// arrives only once a read can observe the revocation.
			done := make(chan error, 1)
			go func() {
				_, err := b.KeyRegistry.MarkRevoked(t.Context(), k.ID, t0)
				done <- err
			}()
			awaitChange(t, ch, func(c keys.Change) bool { return c.Kind == keys.ChangeJTIRevoked && c.JTI == k.JTI })
			revoked, err := b.Store.IsRevoked(t.Context(), k.JTI)
			require.NoError(t, err)
			require.True(t, revoked, "a reported revocation is visible to reads")
			require.NoError(t, <-done)
		}},
		{"Changes/EverySubscriberHearsAChange", func(t *testing.T, b Backend) {
			f := feed(t, b)
			first, second := f.SubscribeChanges(t.Context()), f.SubscribeChanges(t.Context())
			saveKeypairs(t, b.Store, keypair("kid-1", t0))
			awaitChange(t, first, isKeys)
			awaitChange(t, second, isKeys)
		}},
		{"Changes/FeedClosesWithItsContext", func(t *testing.T, b Backend) {
			subCtx, cancel := context.WithCancel(t.Context())
			ch := feed(t, b).SubscribeChanges(subCtx)
			cancel()
			timeout := time.After(changeWait)
			for {
				select {
				case _, ok := <-ch:
					if !ok {
						return
					}
				case <-timeout:
					t.Fatalf("change feed still open %s after its context ended", changeWait)
				}
			}
		}},
	}
}
