package sqlite

import (
	"context"
	"sync"

	"github.com/onhotpath/tempogate/keys"
)

// changeBuffer is how many changes a subscriber may fall behind by before
// further ones are dropped. Changes are rare (a key rotation, an admin
// revoke), so this only matters for a stuck subscriber.
const changeBuffer = 16

// changeHub is the store's keys.ChangeFeed: an in-process fan-out of the
// changes written through this *Store. SQLite has no cross-process
// notification, so a write by another process (`tempogate keys generate`
// next to a running `serve`) is never reported here; consumers pick it up
// on their periodic reload, exactly as they did before the feed existed.
// In-process rather than a no-op so the default backend exercises the same
// consumer wiring a Postgres LISTEN/NOTIFY feed will drive.
type changeHub struct {
	mu   sync.Mutex
	subs map[chan keys.Change]struct{}
}

// SubscribeChanges satisfies keys.ChangeFeed.
func (s *Store) SubscribeChanges(ctx context.Context) <-chan keys.Change {
	return s.changes.subscribe(ctx)
}

func (h *changeHub) subscribe(ctx context.Context) <-chan keys.Change {
	ch := make(chan keys.Change, changeBuffer)
	h.mu.Lock()
	if h.subs == nil {
		h.subs = map[chan keys.Change]struct{}{}
	}
	h.subs[ch] = struct{}{}
	h.mu.Unlock()

	go func() {
		<-ctx.Done()
		h.mu.Lock()
		delete(h.subs, ch)
		close(ch)
		h.mu.Unlock()
	}()
	return ch
}

// publish is called only after the write it describes has committed, and
// never blocks: a full subscriber misses the change.
func (h *changeHub) publish(c keys.Change) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- c:
		default:
		}
	}
}
