package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/onhotpath/tempogate/admin"
)

func (s *Store) SaveIntegrationKey(ctx context.Context, k admin.IntegrationKey) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO integration_keys
		   (id, namespace, role, owner, jti, created_at, expires_at, revoked_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		k.ID, k.Namespace, string(k.Role), k.Owner, k.JTI, k.CreatedAt, k.ExpiresAt, k.RevokedAt,
	)
	if err != nil {
		return fmt.Errorf("sqlite: save integration key: %w", err)
	}
	return nil
}

func (s *Store) IntegrationKeyByID(ctx context.Context, id string) (admin.IntegrationKey, error) {
	var (
		k       admin.IntegrationKey
		roleStr string
		expires sql.NullTime
		revoked sql.NullTime
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT id, namespace, role, owner, jti, created_at, expires_at, revoked_at
		 FROM integration_keys
		 WHERE id = ?`,
		id,
	).Scan(&k.ID, &k.Namespace, &roleStr, &k.Owner, &k.JTI, &k.CreatedAt, &expires, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return admin.IntegrationKey{}, fmt.Errorf("%w: %s", admin.ErrIntegrationKeyNotFound, id)
	}
	if err != nil {
		return admin.IntegrationKey{}, fmt.Errorf("sqlite: integration key by id: %w", err)
	}
	k.Role = admin.Role(roleStr)
	if expires.Valid {
		t := expires.Time
		k.ExpiresAt = &t
	}
	if revoked.Valid {
		t := revoked.Time
		k.RevokedAt = &t
	}
	return k, nil
}

// defaultListLimit is the page size the store falls back to when the caller
// passes a non-positive Limit. The HTTP handler clamps before reaching here,
// but the store is also reachable from other callers (cleanup jobs, future
// internal tools), so it normalises at its own boundary rather than trusting
// every upstream to do the right thing. The value mirrors admin.defaultListLimit;
// keeping them aligned is a soft contract (the handler's clamp is authoritative
// for HTTP traffic) but worth restating for direct callers.
const defaultListLimit = 50

// ListIntegrationKeys fetches limit+1 rows so the calling handler can detect
// "has more" without a separate COUNT. Ordering is id DESC, which under
// UUIDv7's monotonic time-bits is equivalent to created_at DESC with a
// guaranteed unique tiebreaker — concurrent inserts can never reshuffle a
// paginating client's view because new rows always land with a higher id than
// anything already returned.
//
// Non-positive Limit values are normalised to defaultListLimit at the
// function boundary so a caller that bypasses the handler's clamp cannot
// turn Limit=-1 into LIMIT 0 (a silent "no results" that masks a bug).
func (s *Store) ListIntegrationKeys(ctx context.Context, f admin.ListFilter) ([]admin.IntegrationKey, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = defaultListLimit
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT id, namespace, role, owner, jti, created_at, expires_at, revoked_at
		 FROM integration_keys
		 WHERE (? = '' OR owner = ?)
		   AND (? = '' OR namespace = ?)
		   AND (? = '' OR id < ?)
		 ORDER BY id DESC
		 LIMIT ?`,
		f.Owner, f.Owner,
		f.Namespace, f.Namespace,
		f.Cursor, f.Cursor,
		limit+1,
	)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list integration keys: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]admin.IntegrationKey, 0, limit+1)
	for rows.Next() {
		var (
			k       admin.IntegrationKey
			roleStr string
			expires sql.NullTime
			revoked sql.NullTime
		)
		if err := rows.Scan(&k.ID, &k.Namespace, &roleStr, &k.Owner, &k.JTI, &k.CreatedAt, &expires, &revoked); err != nil {
			return nil, fmt.Errorf("sqlite: scan integration key: %w", err)
		}
		k.Role = admin.Role(roleStr)
		if expires.Valid {
			t := expires.Time
			k.ExpiresAt = &t
		}
		if revoked.Valid {
			t := revoked.Time
			k.RevokedAt = &t
		}
		out = append(out, k)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: rows: %w", err)
	}
	return out, nil
}

// MarkIntegrationKeyRevoked is idempotent. The UPDATE stamps revoked_at only
// when it is currently NULL (`WHERE revoked_at IS NULL`); the RETURNING jti
// fires regardless via a second guarded read so a second call returns the
// same value the first one did. An unknown id reports
// ErrIntegrationKeyNotFound, distinguishing "never existed" from "already
// revoked".
//
// The same transaction also writes the jti into jti_denylist (INSERT OR
// IGNORE, since a second revoke must remain a no-op). Both rows live or die
// together: a crash between the two would otherwise leave the verifier
// accepting a token whose integration-key row says revoked, or rejecting a
// token whose row says active.
func (s *Store) MarkIntegrationKeyRevoked(ctx context.Context, id string) (string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("sqlite: begin tx for mark revoked: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var jti string
	err = tx.QueryRowContext(ctx,
		`SELECT jti FROM integration_keys WHERE id = ?`, id,
	).Scan(&jti)
	if errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("%w: %s", admin.ErrIntegrationKeyNotFound, id)
	}
	if err != nil {
		return "", fmt.Errorf("sqlite: mark revoked: %w", err)
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE integration_keys
		 SET revoked_at = CURRENT_TIMESTAMP
		 WHERE id = ? AND revoked_at IS NULL`,
		id,
	); err != nil {
		return "", fmt.Errorf("sqlite: mark revoked update: %w", err)
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT OR IGNORE INTO jti_denylist (jti, revoked_at)
		 VALUES (?, CURRENT_TIMESTAMP)`,
		jti,
	); err != nil {
		return "", fmt.Errorf("sqlite: mark revoked denylist insert: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("sqlite: commit mark revoked: %w", err)
	}
	return jti, nil
}
