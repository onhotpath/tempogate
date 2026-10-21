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

// ErrDuplicateAuthCode is returned by SaveAuthCode when a code with the same
// value (hash) already exists. With 256 bits of entropy a collision is not expected;
// callers may still distinguish it.
var ErrDuplicateAuthCode = errors.New("sqlite: auth code with this value already exists")

func (s *Store) SaveAuthCode(ctx context.Context, ac oidc.AuthCode) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO auth_codes
		   (code_hash, client_id, redirect_uri, email, scope,
		    code_challenge, code_challenge_method, nonce, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		secretHash(ac.Code), ac.ClientID, ac.RedirectURI, ac.Email, ac.Scope,
		ac.CodeChallenge, ac.CodeChallengeMethod, ac.Nonce, ac.CreatedAt, ac.ExpiresAt,
	)
	if err != nil {
		var sqliteErr *sqlite3.Error
		if errors.As(err, &sqliteErr) && sqliteErr.Code() == sqlite3lib.SQLITE_CONSTRAINT_PRIMARYKEY {
			return ErrDuplicateAuthCode
		}
		return fmt.Errorf("sqlite: save auth code: %w", err)
	}
	return nil
}

// ConsumeAuthCode atomically deletes and returns the authorization code,
// matched by its hash (the code itself is never stored). The
// DELETE ... RETURNING is a single statement, so the max-1-conn store cannot
// hand the same code to two concurrent /token calls: the loser sees zero rows
// and gets oidc.ErrAuthCodeNotFound. Single-use falls out of the same
// property — a replayed code finds the row already gone. Expiry is the
// caller's concern; an expired code is still returned and then rejected.
func (s *Store) ConsumeAuthCode(ctx context.Context, code string) (oidc.AuthCode, error) {
	ac := oidc.AuthCode{Code: code}
	err := s.db.QueryRowContext(ctx,
		`DELETE FROM auth_codes WHERE code_hash = ?
		 RETURNING client_id, redirect_uri, email, scope,
		           code_challenge, code_challenge_method, nonce, created_at, expires_at`,
		secretHash(code),
	).Scan(
		&ac.ClientID, &ac.RedirectURI, &ac.Email, &ac.Scope,
		&ac.CodeChallenge, &ac.CodeChallengeMethod, &ac.Nonce, &ac.CreatedAt, &ac.ExpiresAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return oidc.AuthCode{}, oidc.ErrAuthCodeNotFound
	}
	if err != nil {
		return oidc.AuthCode{}, fmt.Errorf("sqlite: consume auth code: %w", err)
	}
	return ac, nil
}
