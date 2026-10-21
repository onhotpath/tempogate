package keys

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewFxAppliesEncryptionKey(t *testing.T) {
	store := &rewritableStore{}
	k, err := newFx(fxParams{Store: store, EncryptionKey: base64.StdEncoding.EncodeToString(testKEK)})
	require.NoError(t, err)
	k.genOpts = append(k.genOpts, WithRSABits(2048))
	require.NoError(t, k.Init(context.Background()))
	require.True(t, isEncrypted(storedPEM(t, store)[0]))

	plain, err := newFx(fxParams{Store: store})
	require.NoError(t, err)
	require.ErrorIs(t, plain.Init(context.Background()), ErrNoEncryptionKey)
}

func TestNewFxRejectsMalformedEncryptionKey(t *testing.T) {
	_, err := newFx(fxParams{Store: &rewritableStore{}, EncryptionKey: "short"})
	require.Error(t, err)
}

var errStore = errors.New("store down")

// failingStore fails the operation named by fail.
type failingStore struct {
	rewritableStore
	fail string
}

func (s *failingStore) SaveKeypair(ctx context.Context, kp Keypair) error {
	if s.fail == "save" {
		return errStore
	}
	return s.rewritableStore.SaveKeypair(ctx, kp)
}

func (s *failingStore) LoadKeypairs(ctx context.Context) ([]Keypair, error) {
	if s.fail == "load" {
		return nil, errStore
	}
	return s.rewritableStore.LoadKeypairs(ctx)
}

func (s *failingStore) UpdateKeypairPrivatePEM(ctx context.Context, kid string, pem []byte) error {
	if s.fail == "update" {
		return errStore
	}
	return s.rewritableStore.UpdateKeypairPrivatePEM(ctx, kid, pem)
}

func TestStoreErrorsPropagate(t *testing.T) {
	ctx := context.Background()
	require.ErrorIs(t, testKeys(&failingStore{fail: "save"}, testKEK).Init(ctx), errStore)
	_, err := testKeys(&failingStore{fail: "save"}, testKEK).Generate(ctx, false)
	require.ErrorIs(t, err, errStore)

	_, err = testKeys(&failingStore{fail: "load"}, testKEK).EncryptStored(ctx, &rewritableStore{})
	require.ErrorIs(t, err, errStore)

	s := &failingStore{}
	require.NoError(t, testKeys(s, nil).Init(ctx))
	s.fail = "update"
	_, err = testKeys(s, testKEK).EncryptStored(ctx, s)
	require.ErrorIs(t, err, errStore)
}

func TestWrongLengthKeyFailsEveryOperation(t *testing.T) {
	ctx := context.Background()
	k := testKeys(&rewritableStore{}, []byte("short"))
	_, err := k.Generate(ctx, false)
	require.Error(t, err)
	_, err = k.EncryptStored(ctx, &rewritableStore{})
	require.Error(t, err)
}

// TestSignerAndVerifierShareTheAccessAudience: what the Signer stamps on
// access tokens (OIDC_ACCESS_TOKEN_AUDIENCE) is exactly what the Verifier
// requires, and an empty audience is a startup error rather than tokens with
// no aud for Temporal to check.
func TestSignerAndVerifierShareTheAccessAudience(t *testing.T) {
	k := testKeys(&rewritableStore{}, nil)
	require.NoError(t, k.Init(context.Background()))

	signer, err := newSigner(signerParams{Keys: k, Issuer: "https://tg.test", AccessTokenAudience: "temporal-prod"})
	require.NoError(t, err)
	v, err := newVerifier(verifierParams{Keys: k, Issuer: "https://tg.test", AccessTokenAudience: "temporal-prod"})
	require.NoError(t, err)

	signed, _, err := signer.Mint(context.Background(), MintRequest{Subject: "alice", TTL: time.Minute})
	require.NoError(t, err)
	tok, err := v.Verify(context.Background(), signed)
	require.NoError(t, err)
	aud, _ := tok.Audience()
	require.Equal(t, []string{"temporal-prod"}, aud)

	other, err := newVerifier(verifierParams{Keys: k, Issuer: "https://tg.test", AccessTokenAudience: "elsewhere"})
	require.NoError(t, err)
	_, err = other.Verify(context.Background(), signed)
	require.Error(t, err)

	_, err = newSigner(signerParams{Keys: k, Issuer: "https://tg.test"})
	require.Error(t, err)
	_, err = newVerifier(verifierParams{Keys: k, Issuer: "https://tg.test"})
	require.Error(t, err)
}
