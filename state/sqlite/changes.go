package sqlite

import (
	"context"

	"github.com/onhotpath/tempogate/keys"
)

// SubscribeChanges satisfies keys.ChangeFeed with an in-process fan-out of
// the changes written through this *Store. SQLite has no cross-process
// notification, so a write by another process (`tempogate keys generate`
// next to a running `serve`) is never reported here; consumers pick it up
// on their periodic reload, exactly as they did before the feed existed.
// In-process rather than a no-op so the default backend exercises the same
// consumer wiring Postgres LISTEN/NOTIFY drives.
func (s *Store) SubscribeChanges(ctx context.Context) <-chan keys.Change {
	return s.changes.Subscribe(ctx)
}
