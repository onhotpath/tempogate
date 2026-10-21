package keys

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var (
	testKEK  = bytes.Repeat([]byte{0x42}, 32)
	otherKEK = bytes.Repeat([]byte{0x24}, 32)
)

// rewritableStore is fakeKeyStore plus the in-place rewrite `keys encrypt`
// needs.
type rewritableStore struct{ fakeKeyStore }

func (s *rewritableStore) UpdateKeypairPrivatePEM(_ context.Context, kid string, privatePEM []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.kps {
		if s.kps[i].Kid == kid {
			s.kps[i].PrivatePEM = privatePEM
		}
	}
	return nil
}

func testKeys(store KeyStore, kek []byte) *Keys {
	opts := []Option{WithStore(store), WithGenerateOptions(WithRSABits(2048))}
	if kek != nil {
		opts = append(opts, WithEncryptionKey(kek))
	}
	return New(opts...)
}

func storedPEM(t *testing.T, s *rewritableStore) [][]byte {
	t.Helper()
	kps, err := s.LoadKeypairs(context.Background())
	require.NoError(t, err)
	out := make([][]byte, len(kps))
	for i, kp := range kps {
		out[i] = kp.PrivatePEM
	}
	return out
}

// requireSigns proves a loaded keypair is the real private key: it mints a
// token that verifies against the same aggregate.
func requireSigns(t *testing.T, k *Keys) {
	t.Helper()
	tok, _, err := NewSigner(WithKeys(k)).Mint(context.Background(), MintRequest{Subject: "alice@example.com", TTL: time.Minute})
	require.NoError(t, err)
	_, err = NewVerifier(WithKeys(k)).Verify(context.Background(), tok)
	require.NoError(t, err)
}

func TestEncryptionKeyStoresCiphertextAndLoadsPlaintext(t *testing.T) {
	ctx := context.Background()
	store := &rewritableStore{}
	k := testKeys(store, testKEK)
	require.NoError(t, k.Init(ctx))

	stored := storedPEM(t, store)
	require.Len(t, stored, 1)
	require.True(t, bytes.HasPrefix(stored[0], []byte(encryptedPEMPrefix)), "stored with the versioned prefix")
	require.NotContains(t, string(stored[0]), "PRIVATE KEY")

	latest, err := k.Latest()
	require.NoError(t, err)
	require.Contains(t, string(latest.PrivatePEM), "BEGIN RSA PRIVATE KEY", "the cache holds the usable key")

	restarted := testKeys(store, testKEK)
	require.NoError(t, restarted.Init(ctx))
	requireSigns(t, restarted)
	require.Empty(t, restarted.UnencryptedKids())
}

func TestGenerateWithEncryptionKeyStoresCiphertext(t *testing.T) {
	ctx := context.Background()
	store := &rewritableStore{}
	_, err := testKeys(store, testKEK).Generate(ctx, false)
	require.NoError(t, err)
	require.True(t, bytes.HasPrefix(storedPEM(t, store)[0], []byte(encryptedPEMPrefix)))
}

func TestMixedPlaintextAndEncryptedRowsLoad(t *testing.T) {
	ctx := context.Background()
	store := &rewritableStore{}
	require.NoError(t, testKeys(store, nil).Init(ctx)) // plaintext, as before the key was set
	_, err := testKeys(store, testKEK).Generate(ctx, true)
	require.NoError(t, err)

	k := testKeys(store, testKEK)
	require.NoError(t, k.Init(ctx))
	require.Len(t, k.All(), 2)
	for _, kp := range k.All() {
		require.Contains(t, string(kp.PrivatePEM), "BEGIN RSA PRIVATE KEY")
	}
	require.Len(t, k.UnencryptedKids(), 1, "the pre-existing plaintext row is reported")
	requireSigns(t, k)
}

func TestEncryptedRowWithoutKeyFailsInit(t *testing.T) {
	ctx := context.Background()
	store := &rewritableStore{}
	require.NoError(t, testKeys(store, testKEK).Init(ctx))

	err := testKeys(store, nil).Init(ctx)
	require.ErrorIs(t, err, ErrNoEncryptionKey)
	require.Contains(t, err.Error(), "KEYS_ENCRYPTION_KEY")

	_, err = testKeys(store, nil).Generate(ctx, true)
	require.ErrorIs(t, err, ErrNoEncryptionKey, "generate must not append a plaintext key next to encrypted ones")
}

func TestWrongEncryptionKeyFailsInit(t *testing.T) {
	ctx := context.Background()
	store := &rewritableStore{}
	require.NoError(t, testKeys(store, testKEK).Init(ctx))

	err := testKeys(store, otherKEK).Init(ctx)
	require.ErrorIs(t, err, ErrDecryptKeypair)
}

// The kid is authenticated with the ciphertext, so a row's private key
// cannot be swapped into another row.
func TestCiphertextIsBoundToKid(t *testing.T) {
	ctx := context.Background()
	store := &rewritableStore{}
	k := testKeys(store, testKEK)
	require.NoError(t, k.Init(ctx))
	_, err := k.Generate(ctx, true)
	require.NoError(t, err)

	store.mu.Lock()
	store.kps[0].PrivatePEM, store.kps[1].PrivatePEM = store.kps[1].PrivatePEM, store.kps[0].PrivatePEM
	store.mu.Unlock()

	require.ErrorIs(t, testKeys(store, testKEK).Init(ctx), ErrDecryptKeypair)
}

func TestEncryptStoredEncryptsPlaintextRowsOnce(t *testing.T) {
	ctx := context.Background()
	store := &rewritableStore{}
	require.NoError(t, testKeys(store, nil).Init(ctx))
	_, err := testKeys(store, nil).Generate(ctx, true)
	require.NoError(t, err)

	k := testKeys(store, testKEK)
	n, err := k.EncryptStored(ctx, store)
	require.NoError(t, err)
	require.Equal(t, 2, n)
	for _, pem := range storedPEM(t, store) {
		require.True(t, bytes.HasPrefix(pem, []byte(encryptedPEMPrefix)))
	}

	n, err = k.EncryptStored(ctx, store)
	require.NoError(t, err)
	require.Zero(t, n, "already-encrypted rows are left alone")

	restarted := testKeys(store, testKEK)
	require.NoError(t, restarted.Init(ctx))
	requireSigns(t, restarted)
}

func TestEncryptStoredWithoutKeyFails(t *testing.T) {
	store := &rewritableStore{}
	_, err := testKeys(store, nil).EncryptStored(context.Background(), store)
	require.ErrorIs(t, err, ErrNoEncryptionKey)
}

func TestLoadEncryptionKey(t *testing.T) {
	raw := bytes.Repeat([]byte{7}, 32)
	std := base64.StdEncoding.EncodeToString(raw)
	file := filepath.Join(t.TempDir(), "kek")
	require.NoError(t, os.WriteFile(file, []byte(std+"\n"), 0o600))

	for name, tc := range map[string]struct {
		value, file string
		want        []byte
		wantErr     string
	}{
		"unset":                          {},
		"std base64":                     {value: std, want: raw},
		"unpadded url base64":            {value: base64.RawURLEncoding.EncodeToString(raw), want: raw},
		"file, trailing newline trimmed": {file: file, want: raw},
		"both set":                       {value: std, file: file, wantErr: "only one of"},
		"not base64":                     {value: "!!!", wantErr: "base64"},
		"wrong length":                   {value: base64.StdEncoding.EncodeToString(raw[:16]), wantErr: "32 bytes"},
		"missing file":                   {file: filepath.Join(t.TempDir(), "nope"), wantErr: "KEYS_ENCRYPTION_KEY_FILE"},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := LoadEncryptionKey(tc.value, tc.file)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestWithEncryptionKeyRejectsWrongLength(t *testing.T) {
	k := New(WithStore(&rewritableStore{}), WithEncryptionKey([]byte("short")))
	require.Error(t, k.Init(context.Background()))
}

func TestMalformedCiphertextFailsInit(t *testing.T) {
	store := &rewritableStore{}
	store.kps = []Keypair{{Kid: "k", Alg: AlgRS256, PrivatePEM: []byte(encryptedPEMPrefix + "!!"), CreatedAt: time.Now()}}
	require.ErrorIs(t, testKeys(store, testKEK).Init(context.Background()), ErrDecryptKeypair)
}

// A mismatched KEK is caught by `keys encrypt`, not at the next boot.
func TestEncryptStoredWithWrongKeyFails(t *testing.T) {
	ctx := context.Background()
	store := &rewritableStore{}
	require.NoError(t, testKeys(store, testKEK).Init(ctx))
	_, err := testKeys(store, otherKEK).EncryptStored(ctx, store)
	require.ErrorIs(t, err, ErrDecryptKeypair)
}

// TestReloadAndRetireOpenEncryptedRows guards the hot-reload path: rows
// written by another process under the KEK must reach the cache decrypted,
// and Retire must hand back the opened keypair, never the stored ciphertext.
func TestReloadAndRetireOpenEncryptedRows(t *testing.T) {
	ctx := context.Background()
	store := &rewritableStore{}
	serving := testKeys(store, testKEK)
	require.NoError(t, serving.Init(ctx))

	rotated, err := testKeys(store, testKEK).Generate(ctx, true)
	require.NoError(t, err)
	require.NoError(t, serving.Reload(ctx))

	latest, err := serving.Latest()
	require.NoError(t, err)
	require.Equal(t, rotated.Kid, latest.Kid)
	for _, kp := range serving.All() {
		require.Contains(t, string(kp.PrivatePEM), "BEGIN RSA PRIVATE KEY")
	}
	requireSigns(t, serving)

	old := serving.All()[0]
	retired, err := serving.Retire(ctx, old.Kid)
	require.NoError(t, err)
	require.True(t, retired.Retired())
	require.Contains(t, string(retired.PrivatePEM), "BEGIN RSA PRIVATE KEY")

	err = testKeys(store, nil).Reload(ctx)
	require.ErrorIs(t, err, ErrNoEncryptionKey, "reload without the KEK must fail, not cache ciphertext")
}
