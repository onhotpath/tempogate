// Package secret is how every backend stores a bearer secret: as its hash,
// so a copy of the database holds nothing a client could present. Sharing
// it keeps the backends' rows interchangeable.
package secret

import (
	"crypto/sha256"
	"encoding/hex"
)

// Hash is the lowercase hex SHA-256 of v, the stored and looked-up form of
// refresh tokens, authorization and device codes and verification-page
// session ids. Unsalted is deliberate: the inputs are 256-bit random, so
// there is nothing to precompute, and a salt would make the lookup a scan.
func Hash(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}
