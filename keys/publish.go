package keys

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// DefaultPublishDelay is how long a new keypair sits in JWKS before it signs.
// It must exceed the time a relying party needs to see the key: Temporal's
// jwtKeyProvider.refreshInterval (1m in Temporal's own config template) plus
// KEYS_RELOAD_INTERVAL.
const DefaultPublishDelay = 5 * time.Minute

// ErrReplacementPending refuses retiring the signing key while every key that
// would take over is still inside its publish delay: relying parties may not
// have fetched it yet, so tokens it signs would be rejected.
var ErrReplacementPending = errors.New("keys: refusing to retire the signing keypair while its replacement is still inside KEYS_PUBLISH_DELAY")

// ReplacementPendingError is the ErrReplacementPending refusal with the
// replacement's kid and the moment it starts signing, so callers can tell the
// operator when to retry.
type ReplacementPendingError struct {
	Kid         string
	ActivatesAt time.Time
}

func (e *ReplacementPendingError) Error() string {
	return fmt.Sprintf("%s (kid=%s signs from %s)",
		ErrReplacementPending, e.Kid, e.ActivatesAt.UTC().Format(time.RFC3339))
}

func (e *ReplacementPendingError) Is(target error) bool { return target == ErrReplacementPending }

// WithPublishDelay sets how long a new keypair is published in JWKS before it
// becomes the signer. Temporal's JWT key provider looks a kid up only in the
// JWKS it fetched on its last refresh and never refetches on an unknown kid,
// so a token signed by a key it has not fetched yet is rejected. Zero signs
// with a new key the moment it is loaded.
//
// Panics on a negative delay so a misconfiguration fails at construction.
func WithPublishDelay(d time.Duration) Option {
	if d < 0 {
		panic("keys: WithPublishDelay requires a non-negative duration")
	}
	return func(k *Keys) { k.publishDelay = d }
}

// Signing returns the keypair that signs new tokens at now: the newest
// non-retired keypair whose publish delay has elapsed. When none has, the
// oldest non-retired keypair signs, so a fresh install or a recovery from
// all-retired signs at once. kps must be sorted by CreatedAt ASC.
func Signing(kps []Keypair, now time.Time, publishDelay time.Duration) (Keypair, bool) {
	var oldest *Keypair
	for i := len(kps) - 1; i >= 0; i-- {
		if kps[i].Retired() {
			continue
		}
		if !now.Before(kps[i].CreatedAt.Add(publishDelay)) {
			return kps[i], true
		}
		oldest = &kps[i]
	}
	if oldest == nil {
		return Keypair{}, false
	}
	return *oldest, true
}

// Signing applies the package-level Signing rule with this aggregate's clock
// and publish delay.
func (k *Keys) Signing(kps []Keypair) (Keypair, bool) {
	return Signing(kps, k.now(), k.publishDelay)
}

// KeypairStatus is a keypair as operators see it in `keys list` and
// GET /admin/signing-keys.
type KeypairStatus struct {
	Keypair

	// Signing is true for the one keypair that signs new tokens now.
	Signing bool

	// ActivatesAt is set on a non-retired keypair that does not sign yet
	// because its publish delay has not elapsed: the moment it starts
	// signing, unless a newer keypair matures first.
	ActivatesAt *time.Time
}

// Statuses reloads from the store and returns every keypair, retired ones
// included, sorted by CreatedAt ASC, with its signing status.
func (k *Keys) Statuses(ctx context.Context) ([]KeypairStatus, error) {
	kps, err := k.Keypairs(ctx)
	if err != nil {
		return nil, err
	}
	now := k.now()
	signing, _ := Signing(kps, now, k.publishDelay)
	out := make([]KeypairStatus, 0, len(kps))
	for _, kp := range kps {
		st := KeypairStatus{Keypair: kp, Signing: !kp.Retired() && kp.Kid == signing.Kid}
		if at := kp.CreatedAt.Add(k.publishDelay); !kp.Retired() && !st.Signing && now.Before(at) {
			st.ActivatesAt = &at
		}
		out = append(out, st)
	}
	return out, nil
}
