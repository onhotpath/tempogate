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

// BootstrapLocker is the optional seam through which a store shared by
// several processes serialises first-boot key generation: replicas starting
// together on an empty database would otherwise each generate (and sign
// with) a key of their own. LockKeyBootstrap runs fn while holding a lock no
// other process sharing the store can hold at the same time, and returns
// fn's error. A single-writer store (SQLite) needs no such lock and does
// not offer one.
type BootstrapLocker interface {
	LockKeyBootstrap(ctx context.Context, fn func(context.Context) error) error
}

// WithBootstrapLocker makes Init load and, if needed, generate under
// locker. Nil keeps Init unlocked.
func WithBootstrapLocker(locker BootstrapLocker) Option {
	return func(k *Keys) { k.bootstrap = locker }
}
