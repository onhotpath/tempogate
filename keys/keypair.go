package keys

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"

	"github.com/onhotpath/tempogate/internal/clock"
)

const (
	AlgRS256       = "RS256"
	defaultRSABits = 4096
)

var ErrUnsupportedAlgorithm = errors.New("keys: unsupported algorithm")

type Keypair struct {
	Kid        string
	Alg        string
	PrivatePEM []byte
	PublicPEM  []byte
	CreatedAt  time.Time
	RetiredAt  *time.Time
}

type generateConfig struct {
	alg     string
	rsaBits int
	now     func() time.Time
}

type GenerateOption func(*generateConfig)

func WithGenAlgorithm(alg string) GenerateOption {
	return func(c *generateConfig) { c.alg = alg }
}

func WithRSABits(bits int) GenerateOption {
	return func(c *generateConfig) { c.rsaBits = bits }
}

// WithNow swaps the clock used to stamp Keypair.CreatedAt. Intended for tests.
func WithNow(now func() time.Time) GenerateOption {
	return func(c *generateConfig) { c.now = now }
}

// GenerateKeypair produces a fresh RSA keypair, marshals both halves to PEM,
// and derives kid from the RFC 7638 JWK thumbprint of the public key. The
// thumbprint is stable for a given public key and distinct across keypairs,
// which gives `--force` rotations a new kid for free.
func GenerateKeypair(opts ...GenerateOption) (Keypair, error) {
	cfg := generateConfig{
		alg:     AlgRS256,
		rsaBits: defaultRSABits,
		now:     clock.Now,
	}
	for _, o := range opts {
		o(&cfg)
	}

	if cfg.alg != AlgRS256 {
		return Keypair{}, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, cfg.alg)
	}

	priv, err := rsa.GenerateKey(rand.Reader, cfg.rsaBits)
	if err != nil {
		return Keypair{}, fmt.Errorf("keys: rsa generate: %w", err)
	}

	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})

	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return Keypair{}, fmt.Errorf("keys: marshal public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})

	pubJWK, err := jwk.Import[jwk.Key](&priv.PublicKey)
	if err != nil {
		return Keypair{}, fmt.Errorf("keys: build jwk: %w", err)
	}
	thumb, err := pubJWK.Thumbprint(crypto.SHA256)
	if err != nil {
		return Keypair{}, fmt.Errorf("keys: thumbprint: %w", err)
	}

	return Keypair{
		Kid:        base64.RawURLEncoding.EncodeToString(thumb),
		Alg:        cfg.alg,
		PrivatePEM: privPEM,
		PublicPEM:  pubPEM,
		CreatedAt:  cfg.now(),
	}, nil
}
