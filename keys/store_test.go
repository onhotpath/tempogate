package keys

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// fakeKeyStore is an in-memory KeyStore that demonstrates the consumer-side
// test pattern: the interface is satisfied structurally inside the test file
// of the package that defines it.
type fakeKeyStore struct {
	mu      sync.Mutex
	kps     []Keypair
	loadErr error
}

func (s *fakeKeyStore) SaveKeypair(_ context.Context, kp Keypair) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.kps = append(s.kps, kp)
	return nil
}

func (s *fakeKeyStore) LoadKeypairs(_ context.Context) ([]Keypair, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loadErr != nil {
		return nil, s.loadErr
	}
	out := make([]Keypair, len(s.kps))
	copy(out, s.kps)
	return out, nil
}

// RetireKeypair mirrors the sqlite store's contract: unknown kid and "last
// active key" are refused, and a repeat retire keeps the first stamp.
func (s *fakeKeyStore) RetireKeypair(_ context.Context, kid string, at time.Time) (Keypair, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx, active := -1, 0
	for i, kp := range s.kps {
		if kp.Kid == kid {
			idx = i
		}
		if kp.RetiredAt == nil {
			active++
		}
	}
	switch {
	case idx < 0:
		return Keypair{}, ErrKeypairNotFound
	case s.kps[idx].RetiredAt != nil:
		return s.kps[idx], nil
	case active <= 1:
		return Keypair{}, ErrLastActiveKeypair
	}
	s.kps[idx].RetiredAt = &at
	return s.kps[idx], nil
}

var _ KeyStore = (*fakeKeyStore)(nil)

type KeyStoreSuite struct {
	suite.Suite

	ctx   context.Context
	store KeyStore
}

func TestKeyStoreSuite(t *testing.T) {
	suite.Run(t, new(KeyStoreSuite))
}

func (s *KeyStoreSuite) SetupTest() {
	s.ctx = context.Background()
	s.store = &fakeKeyStore{}
}

func (s *KeyStoreSuite) TestRoundTrip() {
	now := time.Now().UTC()
	kp := func(kid string, offset time.Duration) Keypair {
		return Keypair{
			Kid:        kid,
			Alg:        "RS256",
			PrivatePEM: []byte("priv-" + kid),
			PublicPEM:  []byte("pub-" + kid),
			CreatedAt:  now.Add(offset),
		}
	}

	cases := []struct {
		name string
		save []Keypair
	}{
		{"empty store returns empty slice", nil},
		{"single keypair", []Keypair{kp("kid-1", 0)}},
		{"multiple keypairs preserve insertion order", []Keypair{
			kp("kid-1", 0),
			kp("kid-2", time.Second),
			kp("kid-3", 2*time.Second),
		}},
	}

	for _, tc := range cases {
		s.Run(tc.name, func() {
			s.SetupTest()

			for _, kp := range tc.save {
				s.Require().NoError(s.store.SaveKeypair(s.ctx, kp))
			}

			got, err := s.store.LoadKeypairs(s.ctx)
			s.Require().NoError(err)
			s.Require().Len(got, len(tc.save))
			for i, want := range tc.save {
				s.Equal(want, got[i])
			}
		})
	}
}

func (s *KeyStoreSuite) TestLoadReturnsCopy() {
	kp := Keypair{Kid: "kid-1", Alg: "RS256", CreatedAt: time.Now().UTC()}
	s.Require().NoError(s.store.SaveKeypair(s.ctx, kp))

	got, err := s.store.LoadKeypairs(s.ctx)
	s.Require().NoError(err)
	s.Require().Len(got, 1)

	got[0].Kid = "mutated"

	again, err := s.store.LoadKeypairs(s.ctx)
	s.Require().NoError(err)
	s.Require().Len(again, 1)
	s.Equal("kid-1", again[0].Kid)
}

// mutexLocker is a BootstrapLocker over an in-process mutex, standing in for
// the advisory lock a shared store takes.
type mutexLocker struct {
	mu    sync.Mutex
	calls int
	err   error
}

func (l *mutexLocker) LockKeyBootstrap(ctx context.Context, fn func(context.Context) error) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls++
	if l.err != nil {
		return l.err
	}
	return fn(ctx)
}

// TestInitUnderABootstrapLockGeneratesOneKey: processes sharing one store
// and one lock agree on a single first key.
func TestInitUnderABootstrapLockGeneratesOneKey(t *testing.T) {
	store, locker := &fakeKeyStore{}, &mutexLocker{}
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			k := New(WithStore(store), WithBootstrapLocker(locker), WithGenerateOptions(WithRSABits(2048)))
			require.NoError(t, k.Init(t.Context()))
		})
	}
	wg.Wait()
	require.Equal(t, 4, locker.calls)
	require.Len(t, store.kps, 1)

	locker.err = errors.New("lock unavailable")
	require.ErrorIs(t, New(WithStore(store), WithBootstrapLocker(locker)).Init(t.Context()), locker.err)
}
