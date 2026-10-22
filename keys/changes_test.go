package keys

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// fakeFeed hands every subscriber the same channel, so a test controls
// exactly which changes arrive and when the feed closes.
type fakeFeed struct {
	ch         chan Change
	subscribed chan struct{}
}

func newFakeFeed() *fakeFeed {
	return &fakeFeed{ch: make(chan Change), subscribed: make(chan struct{}, 1)}
}

func (f *fakeFeed) SubscribeChanges(context.Context) <-chan Change {
	f.subscribed <- struct{}{}
	return f.ch
}

// countingStore counts LoadKeypairs calls, i.e. reloads.
type countingStore struct {
	fakeKeyStore
	loads atomic.Int32
}

func (s *countingStore) LoadKeypairs(ctx context.Context) ([]Keypair, error) {
	s.loads.Add(1)
	return s.fakeKeyStore.LoadKeypairs(ctx)
}

func watch(t *testing.T, k *Keys, interval time.Duration) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- k.Watch(ctx, interval, func(error) {}) }()
	t.Cleanup(func() {
		cancel()
		require.NoError(t, <-done)
	})
}

func TestWatchReloadsOnKeyChangesOnly(t *testing.T) {
	store := &countingStore{}
	feed := newFakeFeed()
	k := New(WithStore(store), WithChangeFeed(feed), WithPublishDelay(0), WithGenerateOptions(WithRSABits(2048)))
	_, err := k.Generate(t.Context(), false)
	require.NoError(t, err)
	watch(t, k, time.Hour)
	<-feed.subscribed

	rotated, err := New(WithStore(store), WithGenerateOptions(WithRSABits(2048))).Generate(t.Context(), true)
	require.NoError(t, err)
	before := store.loads.Load()

	feed.ch <- Change{Kind: ChangeJTIRevoked, JTI: "jti-1"}
	feed.ch <- Change{Kind: ChangeKeys}
	require.Eventually(t, func() bool {
		latest, err := k.Latest()
		return err == nil && latest.Kid == rotated.Kid
	}, 2*time.Second, 5*time.Millisecond, "a key change reloads before the hour-long tick")
	require.Equal(t, before+1, store.loads.Load(), "only the key change reloads")
}

func TestWatchFallsBackToPeriodicReloadWhenTheFeedCloses(t *testing.T) {
	store := &fakeKeyStore{}
	feed := newFakeFeed()
	k := New(WithStore(store), WithChangeFeed(feed), WithPublishDelay(0), WithGenerateOptions(WithRSABits(2048)))
	_, err := k.Generate(t.Context(), false)
	require.NoError(t, err)
	close(feed.ch)
	watch(t, k, 5*time.Millisecond)

	rotated, err := New(WithStore(store), WithGenerateOptions(WithRSABits(2048))).Generate(t.Context(), true)
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		latest, err := k.Latest()
		return err == nil && latest.Kid == rotated.Kid
	}, 2*time.Second, 5*time.Millisecond)
}

// staticChecker answers every lookup with revoked.
type staticChecker bool

func (c staticChecker) IsRevoked(context.Context, string) (bool, error) { return bool(c), nil }

func TestFollowHydratesRevokedJTIs(t *testing.T) {
	feed := newFakeFeed()
	cache := NewDenylistCache(WithDenylistChecker(staticChecker(false)), WithDenylistChangeFeed(feed), WithDenylistTTL(time.Hour))
	revoked, err := cache.IsRevoked(t.Context(), "jti-1")
	require.NoError(t, err)
	require.False(t, revoked, "cached as active for the next hour")

	done := make(chan error, 1)
	go func() { done <- cache.Follow(t.Context()) }()
	<-feed.subscribed
	feed.ch <- Change{Kind: ChangeKeys}
	feed.ch <- Change{Kind: ChangeJTIRevoked, JTI: "jti-1"}
	close(feed.ch)
	require.NoError(t, <-done, "Follow ends with its feed")

	revoked, err = cache.IsRevoked(t.Context(), "jti-1")
	require.NoError(t, err)
	require.True(t, revoked)
	revoked, err = cache.IsRevoked(t.Context(), "jti-2")
	require.NoError(t, err)
	require.False(t, revoked)
}

func TestFollowWithoutAFeedReturnsAtOnce(t *testing.T) {
	require.NoError(t, NewDenylistCache().Follow(t.Context()))
}

func TestFxWiresTheChangeFeed(t *testing.T) {
	feed := newFakeFeed()
	k, err := newFx(fxParams{Store: &fakeKeyStore{}, Changes: feed})
	require.NoError(t, err)
	require.Same(t, feed, k.changes)

	cache := newDenylistCache(denylistParams{Checker: staticChecker(false), Changes: feed})
	require.Same(t, feed, cache.changes)
}
