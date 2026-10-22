// Package changefeed is the in-process fan-out behind every backend's
// keys.ChangeFeed: SQLite publishes the changes written through its own
// *Store, Postgres the notifications its LISTEN connection receives.
package changefeed

import (
	"context"
	"sync"

	"github.com/onhotpath/tempogate/keys"
)

// buffer is how many changes a subscriber may fall behind by before
// further ones are dropped. Changes are rare (a key rotation, an admin
// revoke), so this only matters for a stuck subscriber.
const buffer = 16

// Hub fans a change out to every live subscriber. The zero value is ready
// to use.
type Hub struct {
	mu   sync.Mutex
	subs map[chan keys.Change]struct{}
}

// Subscribe returns a channel of the changes published after it returns,
// closed once ctx is done.
func (h *Hub) Subscribe(ctx context.Context) <-chan keys.Change {
	ch := make(chan keys.Change, buffer)
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

// Publish is called only after the write it describes has committed, and
// never blocks: a full subscriber misses the change.
func (h *Hub) Publish(c keys.Change) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- c:
		default:
		}
	}
}
