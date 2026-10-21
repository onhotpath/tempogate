package sqlite

import (
	"crypto/sha256"
	"encoding/hex"
)

// secretHash is how a bearer secret is stored and looked up (migration
// 0012): the database never holds a value a client could present. Unsalted
// is deliberate: the inputs are 256-bit random, so there is nothing to
// precompute, and a salt would make the lookup a scan.
func secretHash(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}
