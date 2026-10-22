package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// IsRevoked reports whether jti is present in the persistent denylist. It is
// the consumer-side check the keys.Verifier consults (through the in-process
// cache in keys.DenylistCache) to reject a revoked JWT on the hot path.
//
// The lookup uses a covering primary-key probe (SELECT 1 ... WHERE jti = ?)
// so a hit costs a single B-tree descent regardless of denylist size; an
// unknown jti returns (false, nil) so callers can branch without inspecting
// the error.
func (s *Store) IsRevoked(ctx context.Context, jti string) (bool, error) {
	var one int
	err := s.db.QueryRowContext(ctx,
		`SELECT 1 FROM jti_denylist WHERE jti = ?`, jti,
	).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, s.fail("is_revoked", fmt.Errorf("sqlite: is jti revoked: %w", err))
	}
	return true, nil
}
