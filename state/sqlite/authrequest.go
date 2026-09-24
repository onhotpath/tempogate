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

// ErrDuplicateInternalState is returned by SaveAuthRequest when an auth
// request with the given internal_state already exists. With 256 bits of
// entropy a collision is not expected; callers may still distinguish it.
var ErrDuplicateInternalState = errors.New("sqlite: auth request with this internal_state already exists")

func (s *Store) SaveAuthRequest(ctx context.Context, ar oidc.AuthRequest) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO auth_requests
		   (internal_state, client_id, redirect_uri, scope, client_state,
		    code_challenge, code_challenge_method, nonce, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ar.InternalState, ar.ClientID, ar.RedirectURI, ar.Scope, ar.ClientState,
		ar.CodeChallenge, ar.CodeChallengeMethod, ar.Nonce, ar.CreatedAt, ar.ExpiresAt,
	)
	if err != nil {
		var sqliteErr *sqlite3.Error
		if errors.As(err, &sqliteErr) && sqliteErr.Code() == sqlite3lib.SQLITE_CONSTRAINT_PRIMARYKEY {
			return fmt.Errorf("%w: %s", ErrDuplicateInternalState, ar.InternalState)
		}
		return fmt.Errorf("sqlite: save auth request: %w", err)
	}
	return nil
}

// ConsumeAuthRequest atomically deletes and returns the pending request keyed
// by internalState. The DELETE ... RETURNING is a single statement, so the
// max-1-conn store cannot hand the same row to two concurrent callbacks: the
// loser sees zero rows and gets oidc.ErrAuthRequestNotFound. Single-use falls
// out of the same property — a replayed state finds the row already gone.
func (s *Store) ConsumeAuthRequest(ctx context.Context, internalState string) (oidc.AuthRequest, error) {
	var ar oidc.AuthRequest
	err := s.db.QueryRowContext(ctx,
		`DELETE FROM auth_requests WHERE internal_state = ?
		 RETURNING internal_state, client_id, redirect_uri, scope, client_state,
		           code_challenge, code_challenge_method, nonce, created_at, expires_at`,
		internalState,
	).Scan(
		&ar.InternalState, &ar.ClientID, &ar.RedirectURI, &ar.Scope, &ar.ClientState,
		&ar.CodeChallenge, &ar.CodeChallengeMethod, &ar.Nonce, &ar.CreatedAt, &ar.ExpiresAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return oidc.AuthRequest{}, fmt.Errorf("%w: %s", oidc.ErrAuthRequestNotFound, internalState)
	}
	if err != nil {
		return oidc.AuthRequest{}, fmt.Errorf("sqlite: consume auth request: %w", err)
	}
	return ar, nil
}
