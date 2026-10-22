package keys

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
)

// encryptedPEMPrefix marks a private key stored under the key-encryption key
// (KEK). A PEM row starts with "-----BEGIN", so the two never collide and a
// store can hold both while an operator migrates; the version leaves room
// for another scheme later.
const encryptedPEMPrefix = "tempogate-kek:v1:"

const kekBytes = 32 // AES-256

var (
	// ErrNoEncryptionKey means an operation needs the KEK and none is
	// configured: reading an encrypted signing key, or `keys encrypt`.
	ErrNoEncryptionKey = errors.New("keys: no encryption key configured; set KEYS_ENCRYPTION_KEY or KEYS_ENCRYPTION_KEY_FILE")

	// ErrDecryptKeypair means an encrypted signing key does not open under
	// the configured KEK: a different key, or a tampered row.
	ErrDecryptKeypair = errors.New("keys: cannot decrypt signing key; is KEYS_ENCRYPTION_KEY the key it was encrypted with?")
)

// PrivateKeyRewriter is what EncryptStored needs beyond KeyStore: rewriting
// a stored keypair's private half in place.
type PrivateKeyRewriter interface {
	UpdateKeypairPrivatePEM(ctx context.Context, kid string, privatePEM []byte) error
}

// WithEncryptionKey stores private keys AES-256-GCM encrypted under kek
// (32 bytes). Without it, private keys are stored as plain PEM, and an
// encrypted row cannot be read.
func WithEncryptionKey(kek []byte) Option {
	return func(k *Keys) { k.kek = kek }
}

// LoadEncryptionKey resolves the KEK from its configuration: value is the
// base64 key itself, file a path whose content is. Neither set means no KEK
// (nil, nil). The file form is for a mounted Kubernetes Secret.
func LoadEncryptionKey(value, file string) ([]byte, error) {
	switch {
	case value != "" && file != "":
		return nil, errors.New("keys: set only one of KEYS_ENCRYPTION_KEY and KEYS_ENCRYPTION_KEY_FILE")
	case file != "":
		b, err := os.ReadFile(file) // #nosec G304 -- operator-configured path.
		if err != nil {
			return nil, fmt.Errorf("keys: read KEYS_ENCRYPTION_KEY_FILE: %w", err)
		}
		value = string(b)
	case value == "":
		return nil, nil
	}
	return decodeEncryptionKey(strings.TrimSpace(value))
}

// decodeEncryptionKey accepts any base64 alphabet, padded or not, so
// `openssl rand -base64 32` and the url-safe form used for other tempogate
// keys both work.
func decodeEncryptionKey(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
	} {
		kek, err := enc.DecodeString(s)
		if err != nil {
			continue
		}
		if len(kek) != kekBytes {
			return nil, fmt.Errorf("keys: encryption key must decode to %d bytes, got %d", kekBytes, len(kek))
		}
		return kek, nil
	}
	return nil, errors.New("keys: encryption key is not valid base64")
}

// UnencryptedKids lists the keypairs Init loaded in clear although a KEK is
// configured: the ones `tempogate keys encrypt` would rewrite.
func (k *Keys) UnencryptedKids() []string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return append([]string(nil), k.unencrypted...)
}

// EncryptStored rewrites every stored plaintext private key encrypted under
// the KEK and reports how many it rewrote. Already-encrypted rows are only
// checked to open under this KEK, so a mismatched key fails here rather
// than at the next boot. Safe to repeat.
func (k *Keys) EncryptStored(ctx context.Context, rw PrivateKeyRewriter) (int, error) {
	aead, err := k.cipher()
	if err != nil {
		return 0, err
	}
	if aead == nil {
		return 0, ErrNoEncryptionKey
	}
	stored, err := k.store.LoadKeypairs(ctx)
	if err != nil {
		return 0, fmt.Errorf("keys: load keypairs: %w", err)
	}
	n := 0
	for _, kp := range stored {
		if isEncrypted(kp.PrivatePEM) {
			if _, err := openPEM(aead, kp); err != nil {
				return n, err
			}
			continue
		}
		sealed, err := sealPEM(aead, kp.Kid, kp.PrivatePEM)
		if err != nil {
			return n, err
		}
		if err := rw.UpdateKeypairPrivatePEM(ctx, kp.Kid, sealed); err != nil {
			return n, fmt.Errorf("keys: rewrite keypair %s: %w", kp.Kid, err)
		}
		n++
	}
	return n, nil
}

// cipher returns the AEAD for the configured KEK, or nil when none is set.
func (k *Keys) cipher() (cipher.AEAD, error) {
	if k.kek == nil {
		return nil, nil
	}
	if len(k.kek) != kekBytes {
		return nil, fmt.Errorf("keys: encryption key must be %d bytes, got %d", kekBytes, len(k.kek))
	}
	block, err := aes.NewCipher(k.kek)
	if err != nil {
		return nil, fmt.Errorf("keys: encryption key: %w", err)
	}
	return cipher.NewGCM(block)
}

// openStored returns the stored keypairs with usable private keys, and the
// kids of those stored in clear while a KEK is configured.
func (k *Keys) openStored(stored []Keypair) ([]Keypair, []string, error) {
	aead, err := k.cipher()
	if err != nil {
		return nil, nil, err
	}
	var unencrypted []string
	out := make([]Keypair, 0, len(stored))
	for _, kp := range stored {
		if !isEncrypted(kp.PrivatePEM) {
			if aead != nil {
				unencrypted = append(unencrypted, kp.Kid)
			}
			out = append(out, kp)
			continue
		}
		if aead == nil {
			return nil, nil, fmt.Errorf("%w (keypair %s is encrypted)", ErrNoEncryptionKey, kp.Kid)
		}
		pem, err := openPEM(aead, kp)
		if err != nil {
			return nil, nil, err
		}
		kp.PrivatePEM = pem
		out = append(out, kp)
	}
	return out, unencrypted, nil
}

// sealForStore returns kp as it should be persisted: encrypted when a KEK
// is configured.
func (k *Keys) sealForStore(kp Keypair) (Keypair, error) {
	aead, err := k.cipher()
	if err != nil || aead == nil {
		return kp, err
	}
	sealed, err := sealPEM(aead, kp.Kid, kp.PrivatePEM)
	if err != nil {
		return Keypair{}, err
	}
	kp.PrivatePEM = sealed
	return kp, nil
}

func isEncrypted(privatePEM []byte) bool {
	return bytes.HasPrefix(privatePEM, []byte(encryptedPEMPrefix))
}

// kidAAD binds a ciphertext to its row, so one keypair's private key cannot
// be copied over another's and still open.
func kidAAD(kid string) []byte { return []byte("tempogate keypair " + kid) }

func sealPEM(aead cipher.AEAD, kid string, privatePEM []byte) ([]byte, error) {
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("keys: nonce: %w", err)
	}
	ct := aead.Seal(nonce, nonce, privatePEM, kidAAD(kid))
	return []byte(encryptedPEMPrefix + base64.RawStdEncoding.EncodeToString(ct)), nil
}

func openPEM(aead cipher.AEAD, kp Keypair) ([]byte, error) {
	raw, err := base64.RawStdEncoding.DecodeString(string(kp.PrivatePEM[len(encryptedPEMPrefix):]))
	if err != nil || len(raw) < aead.NonceSize() {
		return nil, fmt.Errorf("%w (keypair %s is malformed)", ErrDecryptKeypair, kp.Kid)
	}
	nonce, ct := raw[:aead.NonceSize()], raw[aead.NonceSize():]
	pem, err := aead.Open(nil, nonce, ct, kidAAD(kp.Kid))
	if err != nil {
		return nil, fmt.Errorf("%w (keypair %s)", ErrDecryptKeypair, kp.Kid)
	}
	return pem, nil
}
