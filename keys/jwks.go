package keys

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
)

var ErrNotRSAPublicKey = errors.New("keys: public key is not RSA")

// JWK is the RFC 7517 public-key projection of a Keypair: the minimum a
// relying party needs to verify a tempogate-signed JWT. N and E are the
// Base64urlUInt encodings of the RSA modulus and exponent per RFC 7518
// §6.3.1; the package leaves the kty/use envelope to the HTTP layer that
// owns the wire contract.
type JWK struct {
	Kid string
	Alg string
	N   string
	E   string
}

// PublicJWKS projects every published keypair's public half to a JWK, in
// CreatedAt ASC order. Relying parties select by Kid, so the order is
// informational. Publishing non-retired keys keeps verification working
// across a --force rotation; dropping retired keys after their grace is what
// makes retirement a kill switch at relying parties such as Temporal, which
// trust JWKS alone.
func (k *Keys) PublicJWKS() ([]JWK, error) {
	kps := k.Published()
	out := make([]JWK, 0, len(kps))
	for _, kp := range kps {
		j, err := publicJWK(kp)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, nil
}

func publicJWK(kp Keypair) (JWK, error) {
	block, _ := pem.Decode(kp.PublicPEM)
	if block == nil {
		return JWK{}, fmt.Errorf("keys: decode public PEM (kid=%s)", kp.Kid)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return JWK{}, fmt.Errorf("keys: parse public key (kid=%s): %w", kp.Kid, err)
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return JWK{}, fmt.Errorf("%w (kid=%s)", ErrNotRSAPublicKey, kp.Kid)
	}
	return JWK{
		Kid: kp.Kid,
		Alg: kp.Alg,
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}, nil
}
