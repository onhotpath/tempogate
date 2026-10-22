package keys

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// DefaultRetirementGrace matches the human access-token TTL, so every token
// signed just before a retirement can live out its natural life.
const DefaultRetirementGrace = 4 * time.Hour

var (
	ErrKeypairNotFound = errors.New("keys: keypair not found")

	// ErrLastActiveKeypair refuses a retirement that would leave the signer
	// with nothing to sign with; the operator rotates first.
	ErrLastActiveKeypair = errors.New("keys: refusing to retire the only active keypair; run `tempogate keys generate --force` first")
)

// WithRetirementGrace sets how long a retired keypair stays in JWKS and keeps
// verifying, so tokens already in flight survive the relying parties' JWKS
// refresh. Zero unpublishes a key the moment it is retired.
//
// Panics on a negative grace so a misconfiguration fails at construction.
func WithRetirementGrace(d time.Duration) Option {
	if d < 0 {
		panic("keys: WithRetirementGrace requires a non-negative duration")
	}
	return func(k *Keys) { k.grace = d }
}

// Retired reports whether the keypair has been retired. A retired keypair
// never signs; it still verifies until its grace elapses.
func (kp Keypair) Retired() bool { return kp.RetiredAt != nil }

// Published returns the keypairs relying parties may verify against: every
// non-retired keypair plus retired ones still inside their grace. JWKS and
// tempogate's own Verifier both use this set, so a kid past grace stops
// verifying everywhere tempogate controls at the same moment.
func (k *Keys) Published() []Keypair {
	now := k.now()
	all := k.All()
	out := make([]Keypair, 0, len(all))
	for _, kp := range all {
		if !kp.Retired() || now.Before(kp.RetiredAt.Add(k.grace)) {
			out = append(out, kp)
		}
	}
	return out
}

// Reload replaces the in-memory keypair set with the store's, so a keypair
// generated or retired by another process (`tempogate keys ...`) takes
// effect without a restart. On error the current set is kept.
func (k *Keys) Reload(ctx context.Context) error {
	stored, err := k.store.LoadKeypairs(ctx)
	if err != nil {
		return fmt.Errorf("keys: load keypairs: %w", err)
	}
	kps, unencrypted, err := k.openStored(stored)
	if err != nil {
		return err
	}
	k.swap(kps, unencrypted)
	return nil
}

// Keypairs reloads from the store and returns every keypair, retired ones
// included, sorted by CreatedAt ASC.
func (k *Keys) Keypairs(ctx context.Context) ([]Keypair, error) {
	if err := k.Reload(ctx); err != nil {
		return nil, err
	}
	return k.All(), nil
}

// RetireOption configures Keys.Retire.
type RetireOption func(*retireConfig)

type retireConfig struct {
	force bool
}

// RetireForce retires the signing keypair even when the key that would take
// over is still inside its publish delay. Use it when the signing key is
// compromised: relying parties may reject new tokens until they next refresh
// JWKS. It never bypasses the "only key that can sign" refusal.
func RetireForce() RetireOption {
	return func(c *retireConfig) { c.force = true }
}

// Retire marks kid retired, then reloads so this process stops signing with
// it immediately. The store enforces the "never retire the only active key"
// rule atomically, so two concurrent retirements cannot both succeed.
// Retiring the current signer while its replacement is still inside the
// publish delay is refused with ErrReplacementPending unless RetireForce is
// passed. Retiring an already-retired kid returns it unchanged, keeping the
// original grace window.
func (k *Keys) Retire(ctx context.Context, kid string, opts ...RetireOption) (Keypair, error) {
	var cfg retireConfig
	for _, o := range opts {
		o(&cfg)
	}
	if !cfg.force {
		if err := k.checkReplacementPublished(ctx, kid); err != nil {
			return Keypair{}, err
		}
	}
	kp, err := k.store.RetireKeypair(ctx, kid, k.now())
	if err != nil {
		return Keypair{}, err
	}
	if err := k.Reload(ctx); err != nil {
		return Keypair{}, err
	}
	// Hand back the reloaded copy, whose private key went through
	// openStored, never the store's possibly encrypted row.
	for _, c := range k.All() {
		if c.Kid == kp.Kid {
			return c, nil
		}
	}
	return Keypair{}, fmt.Errorf("%w (kid=%s)", ErrKeypairNotFound, kp.Kid)
}

// checkReplacementPublished refuses retiring the current signer when the
// keypair that would sign next has not passed its publish delay. Anything
// else (not the signer, no replacement at all) is left to the store, which
// owns the atomic last-active guard.
func (k *Keys) checkReplacementPublished(ctx context.Context, kid string) error {
	if err := k.Reload(ctx); err != nil {
		return err
	}
	kps := k.All()
	signing, ok := k.Signing(kps)
	if !ok || signing.Kid != kid {
		return nil
	}
	rest := make([]Keypair, 0, len(kps))
	for _, kp := range kps {
		if kp.Kid != kid {
			rest = append(rest, kp)
		}
	}
	next, ok := k.Signing(rest)
	if !ok {
		return nil
	}
	if at := next.CreatedAt.Add(k.publishDelay); k.now().Before(at) {
		return &ReplacementPendingError{Kid: next.Kid, ActivatesAt: at}
	}
	return nil
}

// Watch reloads the keypair set every interval until ctx is done, and also
// at once whenever the change feed (WithChangeFeed) reports a key change.
// The periodic reload stays the correctness path: the feed only shortens
// the wait, and a closed feed leaves the ticker running alone. A failed
// reload is passed to onErr and the previous set stays in service, so a
// transient store error never drops the signing key.
func (k *Keys) Watch(ctx context.Context, interval time.Duration, onErr func(error)) error {
	t := time.NewTicker(interval)
	defer t.Stop()
	var changes <-chan Change
	if k.changes != nil {
		changes = k.changes.SubscribeChanges(ctx)
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		case ch, ok := <-changes:
			if !ok {
				changes = nil // a nil channel never fires: periodic only
				continue
			}
			if ch.Kind != ChangeKeys {
				continue
			}
		}
		if err := k.Reload(ctx); err != nil && ctx.Err() == nil {
			onErr(err)
		}
	}
}

// swap installs kps, whose private keys must already be opened (see
// openStored), as the in-memory set.
func (k *Keys) swap(kps []Keypair, unencrypted []string) {
	sortByCreatedAt(kps)
	k.mu.Lock()
	k.keypairs = kps
	k.unencrypted = unencrypted
	k.mu.Unlock()
}
