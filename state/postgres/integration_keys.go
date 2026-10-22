package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/onhotpath/tempogate/admin"
	"github.com/onhotpath/tempogate/keys"
)

func (s *Store) SaveIntegrationKey(ctx context.Context, k admin.IntegrationKey) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO integration_keys
		   (id, namespace, role, owner, jti, created_at, expires_at, revoked_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		k.ID, k.Namespace, string(k.Role), k.Owner, k.JTI, k.CreatedAt, k.ExpiresAt, k.RevokedAt,
	)
	if err != nil {
		return s.fail("save_integration_key", fmt.Errorf("postgres: save integration key: %w", err))
	}
	return nil
}

const integrationKeyColumns = `id, namespace, role, owner, jti, created_at, expires_at, revoked_at`

func (s *Store) IntegrationKeyByID(ctx context.Context, id string) (admin.IntegrationKey, error) {
	k, err := scanIntegrationKey(s.pool.QueryRow(ctx,
		`SELECT `+integrationKeyColumns+` FROM integration_keys WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return admin.IntegrationKey{}, fmt.Errorf("%w: %s", admin.ErrIntegrationKeyNotFound, id)
	}
	if err != nil {
		return admin.IntegrationKey{}, s.fail("integration_key_by_id", fmt.Errorf("postgres: integration key by id: %w", err))
	}
	return k, nil
}

// defaultListLimit is the page size used for a non-positive Limit, the same
// as state/sqlite's (and admin's); the HTTP handler clamps before this.
const defaultListLimit = 50

// ListIntegrationKeys fetches limit+1 rows so the calling handler can detect
// "has more" without a separate COUNT, newest first by id (UUIDv7). The id
// column is COLLATE "C", so ordering and the cursor compare bytewise, as in
// SQLite.
func (s *Store) ListIntegrationKeys(ctx context.Context, f admin.ListFilter) ([]admin.IntegrationKey, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = defaultListLimit
	}

	rows, err := s.pool.Query(ctx,
		`SELECT `+integrationKeyColumns+`
		 FROM integration_keys
		 WHERE ($1::text = '' OR owner = $1)
		   AND ($2::text = '' OR namespace = $2)
		   AND ($3::text = '' OR id < $3)
		 ORDER BY id DESC
		 LIMIT $4`,
		f.Owner, f.Namespace, f.Cursor, limit+1,
	)
	if err != nil {
		return nil, s.fail("list_integration_keys", fmt.Errorf("postgres: list integration keys: %w", err))
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (admin.IntegrationKey, error) { return scanIntegrationKey(r) })
	if err != nil {
		return nil, s.fail("list_integration_keys", fmt.Errorf("postgres: list integration keys: %w", err))
	}
	return out, nil
}

// MarkIntegrationKeyRevoked is idempotent: revoked_at is stamped with at
// only while NULL, so a second call keeps the first time and returns the
// same jti. An unknown id reports admin.ErrIntegrationKeyNotFound.
//
// The same transaction denylists the jti and queues the change
// notification, so the key row, the denylist and the notification commit
// together: no replica is told of a revocation it cannot read, and none
// misses one that committed (beyond the feed's best-effort delivery).
func (s *Store) MarkIntegrationKeyRevoked(ctx context.Context, id string, at time.Time) (string, error) {
	var jti string
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx,
			`UPDATE integration_keys SET revoked_at = coalesce(revoked_at, $1)
			 WHERE id = $2
			 RETURNING jti`,
			at, id,
		).Scan(&jti); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO jti_denylist (jti, revoked_at) VALUES ($1, $2)
			 ON CONFLICT (jti) DO NOTHING`,
			jti, at,
		); err != nil {
			return err
		}
		return notify(ctx, tx, keys.Change{Kind: keys.ChangeJTIRevoked, JTI: jti})
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("%w: %s", admin.ErrIntegrationKeyNotFound, id)
	}
	if err != nil {
		return "", s.fail("mark_integration_key_revoked", fmt.Errorf("postgres: mark revoked: %w", err))
	}
	return jti, nil
}

func scanIntegrationKey(r pgx.Row) (admin.IntegrationKey, error) {
	var (
		k    admin.IntegrationKey
		role string
	)
	if err := r.Scan(&k.ID, &k.Namespace, &role, &k.Owner, &k.JTI, &k.CreatedAt, &k.ExpiresAt, &k.RevokedAt); err != nil {
		return admin.IntegrationKey{}, err
	}
	k.Role = admin.Role(role)
	return k, nil
}
