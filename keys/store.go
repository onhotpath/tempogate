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
	// SaveKeypair persists kp as given; PrivatePEM is opaque bytes (sealed
	// when a KEK is configured). A duplicate kid fails and leaves the
	// stored keypair unchanged.
	SaveKeypair(ctx context.Context, kp Keypair) error

	// LoadKeypairs returns every keypair, retired ones included, ordered by
	// CreatedAt then Kid.
	LoadKeypairs(ctx context.Context) ([]Keypair, error)

	// RetireKeypair stamps kid retired at the given time and returns it.
	// An already-retired kid is returned unchanged, keeping its original
	// RetiredAt. It refuses with ErrLastActiveKeypair when kid is the only
	// non-retired keypair, atomically, so concurrent retirements can never
	// leave none; an unknown kid is ErrKeypairNotFound.
	RetireKeypair(ctx context.Context, kid string, at time.Time) (Keypair, error)
}
