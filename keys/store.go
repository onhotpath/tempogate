package keys

import (
	"context"
	"time"
)

// KeyStore is the consumer-side state interface for this package.
//
// Per the convention documented in package state, interfaces live with the
// package that uses them; the concrete store satisfies this structurally
// without importing keys/. The type is exported so the composition root can
// inject it (via fx.As) — the convention is about where the interface is
// defined, not its visibility.
type KeyStore interface {
	SaveKeypair(ctx context.Context, kp Keypair) error
	LoadKeypairs(ctx context.Context) ([]Keypair, error)
	RetireKeypair(ctx context.Context, kid string, at time.Time) (Keypair, error)
}
