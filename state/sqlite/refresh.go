package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	sqlite3 "modernc.org/sqlite"
	sqlite3lib "modernc.org/sqlite/lib"

	"github.com/onhotpath/tempogate/oidc"
)

// ErrDuplicateRefreshToken is returned by SaveRefresh when a token with the
// same value already exists. With 256 bits of entropy a collision is not
// expected; callers may still distinguish it.
var ErrDuplicateRefreshToken = errors.New("sqlite: refresh token with this value already exists")

func (s *Store) SaveRefresh(ctx context.Context, r oidc.Refresh) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO refresh_tokens
		   (token, jti, client_id, email, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		r.Token, r.JTI, r.ClientID, r.Email, r.CreatedAt, r.ExpiresAt,
	)
	if err != nil {
		var sqliteErr *sqlite3.Error
		if errors.As(err, &sqliteErr) && sqliteErr.Code() == sqlite3lib.SQLITE_CONSTRAINT_PRIMARYKEY {
			return fmt.Errorf("%w: %s", ErrDuplicateRefreshToken, r.Token)
		}
		return fmt.Errorf("sqlite: save refresh token: %w", err)
	}
	return nil
}

// ConsumeRefresh atomically deletes and returns the refresh token. The
// DELETE ... RETURNING is a single statement, so the max-1-conn store cannot
// hand the same token to two concurrent refreshes: the loser sees zero rows
// and gets oidc.ErrRefreshNotFound. Rotation falls out of the same property —
// every successful exchange consumes the row, so a captured token is usable
// at most once before the legitimate client's next refresh invalidates it.
func (s *Store) ConsumeRefresh(ctx context.Context, token string) (oidc.Refresh, error) {
	var r oidc.Refresh
	err := s.db.QueryRowContext(ctx,
		`DELETE FROM refresh_tokens WHERE token = ?
		 RETURNING token, jti, client_id, email, created_at, expires_at`,
		token,
	).Scan(
		&r.Token, &r.JTI, &r.ClientID, &r.Email, &r.CreatedAt, &r.ExpiresAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return oidc.Refresh{}, fmt.Errorf("%w: %s", oidc.ErrRefreshNotFound, token)
	}
	if err != nil {
		return oidc.Refresh{}, fmt.Errorf("sqlite: consume refresh token: %w", err)
	}
	return r, nil
}
