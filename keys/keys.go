package keys

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/onhotpath/tempogate/internal/clock"
)

var (
	ErrKeypairExists = errors.New("keys: keypair already exists; use --force to rotate")
	ErrNoKeypair     = errors.New("keys: no keypair loaded")
)

type Option func(*Keys)

func WithStore(s KeyStore) Option {
	return func(k *Keys) { k.store = s }
}

func WithAlgorithm(alg string) Option {
	return func(k *Keys) { k.alg = alg }
}

// WithClock swaps the clock used to stamp newly generated keypairs.
// Intended for tests.
func WithClock(now func() time.Time) Option {
	return func(k *Keys) { k.now = now }
}

// WithGenerateOptions threads low-level GenerateKeypair tweaks (e.g.
// WithRSABits in tests) through Keys.Init and Keys.Generate.
func WithGenerateOptions(opts ...GenerateOption) Option {
	return func(k *Keys) { k.genOpts = append(k.genOpts, opts...) }
}

// Keys is the signing-keypair aggregate. It fronts a KeyStore with an
// in-memory cache of loaded keypairs and exposes Init / Generate / Retire as
// the state-transition entry points (boot flow vs. explicit CLI or admin
// action); Reload and Watch keep the cache in step with other processes.
type Keys struct {
	store   KeyStore
	alg     string
	now     func() time.Time
	grace   time.Duration
	genOpts []GenerateOption
	kek     []byte

	publishDelay time.Duration
	changes      ChangeFeed
	bootstrap    BootstrapLocker

	mu          sync.RWMutex
	keypairs    []Keypair
	unencrypted []string
}

func New(opts ...Option) *Keys {
	k := &Keys{
		alg:   AlgRS256,
		now:   clock.Now,
		grace: DefaultRetirementGrace,

		publishDelay: DefaultPublishDelay,
	}
	for _, o := range opts {
		o(k)
	}
	return k
}

// generateOptions builds the GenerateOption slice for an internal generate
// call: algorithm + clock first (so callers can override via WithGenerateOptions
// if they really need to), then any caller-supplied tweaks.
func (k *Keys) generateOptions() []GenerateOption {
	opts := []GenerateOption{
		WithGenAlgorithm(k.alg),
		WithNow(k.now),
	}
	return append(opts, k.genOpts...)
}

// Latest returns the keypair that signs new tokens now (see Signing) from the
// in-memory cache. Init or Generate must be called first; otherwise, or when
// every keypair is retired, ErrNoKeypair is returned.
func (k *Keys) Latest() (Keypair, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	kp, ok := k.Signing(k.keypairs)
	if !ok {
		return Keypair{}, ErrNoKeypair
	}
	return kp, nil
}

// All returns a copy of the in-memory cache, sorted by CreatedAt ASC.
func (k *Keys) All() []Keypair {
	k.mu.RLock()
	defer k.mu.RUnlock()
	out := make([]Keypair, len(k.keypairs))
	copy(out, k.keypairs)
	return out
}

// Generate creates a new keypair and persists it through the store.
// If a keypair already exists and force is false, Generate returns
// ErrKeypairExists (wrapped with the latest kid).
// With force=true, a brand-new keypair is appended: it is published at once
// and signs once the publish delay has passed (see WithPublishDelay); old
// keypairs keep verifying until they are retired (see Retire).
func (k *Keys) Generate(ctx context.Context, force bool) (Keypair, error) {
	stored, err := k.store.LoadKeypairs(ctx)
	if err != nil {
		return Keypair{}, fmt.Errorf("keys: load keypairs: %w", err)
	}

	if len(stored) > 0 && !force {
		latest := pickLatest(stored)
		return Keypair{}, fmt.Errorf("%w (kid=%s)", ErrKeypairExists, latest.Kid)
	}

	// Opening the existing keys first means a rotation without the KEK
	// fails instead of adding a plaintext key beside encrypted ones.
	existing, unencrypted, err := k.openStored(stored)
	if err != nil {
		return Keypair{}, err
	}

	kp, err := GenerateKeypair(k.generateOptions()...)
	if err != nil {
		return Keypair{}, err
	}

	if err := k.save(ctx, kp); err != nil {
		return Keypair{}, err
	}

	k.swap(append(existing, kp), unencrypted)
	return kp, nil
}

// save persists kp, encrypted when a KEK is configured.
func (k *Keys) save(ctx context.Context, kp Keypair) error {
	toStore, err := k.sealForStore(kp)
	if err != nil {
		return err
	}
	if err := k.store.SaveKeypair(ctx, toStore); err != nil {
		return fmt.Errorf("keys: save keypair: %w", err)
	}
	return nil
}

func sortByCreatedAt(kps []Keypair) {
	sort.SliceStable(kps, func(i, j int) bool {
		if kps[i].CreatedAt.Equal(kps[j].CreatedAt) {
			return kps[i].Kid < kps[j].Kid
		}
		return kps[i].CreatedAt.Before(kps[j].CreatedAt)
	})
}

func pickLatest(kps []Keypair) Keypair {
	latest := kps[0]
	for _, kp := range kps[1:] {
		if kp.CreatedAt.After(latest.CreatedAt) {
			latest = kp
		}
	}
	return latest
}
