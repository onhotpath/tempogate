package postgres

import (
	"context"
	"fmt"
)

// IsRevoked reports whether jti is present in the persistent denylist. It is
// the consumer-side check the keys.Verifier consults (through the in-process
// cache in keys.DenylistCache) to reject a revoked JWT on the hot path; an
// unknown jti returns (false, nil).
func (s *Store) IsRevoked(ctx context.Context, jti string) (bool, error) {
	ctx, op := s.ops.Start(ctx, "is_revoked")
	defer op.End()
	var revoked bool
	if err := s.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM jti_denylist WHERE jti = $1)`, jti,
	).Scan(&revoked); err != nil {
		return false, op.Fail(fmt.Errorf("postgres: is jti revoked: %w", err))
	}
	return revoked, nil
}
