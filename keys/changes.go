package keys

import "context"

// ChangeKind says which cached state a Change invalidates.
type ChangeKind uint8

const (
	// ChangeKeys means a keypair was added, retired or rewritten.
	ChangeKeys ChangeKind = iota + 1

	// ChangeJTIRevoked means Change.JTI entered the denylist.
	ChangeJTIRevoked
)

// Change is a hint that state this package caches has changed in the store.
type Change struct {
	Kind ChangeKind

	// JTI is the revoked token id when Kind is ChangeJTIRevoked.
	JTI string
}

// ChangeFeed is the optional consumer-side seam through which a state store
// tells this process that keys or the jti denylist changed (see state/doc.go
// for the full contract). A backend may implement it natively (Postgres
// LISTEN/NOTIFY), in-process, or not at all.
//
// Changes are hints, never the record: one may be dropped, delayed,
// coalesced, duplicated or spurious, and none arrives from a backend that
// lost its listener. Consumers therefore keep their periodic paths
// (KEYS_RELOAD_INTERVAL, the denylist cache TTL) for correctness and use a
// change only to react sooner. A change is delivered only after the write
// it describes is committed, so a read made on receipt observes it.
type ChangeFeed interface {
	// SubscribeChanges returns a channel of changes committed after it
	// returns. The channel is closed once ctx is done, and may close
	// earlier if the backend gives up on delivery; the subscriber then
	// carries on with its periodic path alone. Sending never blocks the
	// writer, so a subscriber that falls behind loses changes.
	SubscribeChanges(ctx context.Context) <-chan Change
}

// WithChangeFeed makes Watch reload as soon as feed reports a key change,
// in addition to its periodic reload. Nil keeps periodic reload only.
func WithChangeFeed(feed ChangeFeed) Option {
	return func(k *Keys) { k.changes = feed }
}

// WithDenylistChangeFeed makes Follow hydrate the cache from feed's jti
// revocations. Nil leaves the cache on its TTL alone.
func WithDenylistChangeFeed(feed ChangeFeed) DenylistCacheOption {
	return func(c *DenylistCache) { c.changes = feed }
}

// Follow hydrates the cache with every revocation the change feed reports
// until ctx is done or the feed closes, so a jti revoked in another process
// (or replica) is refused before its cached "active" entry expires. Without
// a feed it returns at once; the TTL keeps bounding staleness either way.
func (c *DenylistCache) Follow(ctx context.Context) error {
	if c.changes == nil {
		return nil
	}
	for ch := range c.changes.SubscribeChanges(ctx) {
		if ch.Kind == ChangeJTIRevoked {
			c.Hydrate(ch.JTI)
		}
	}
	return nil
}
