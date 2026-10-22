package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/onhotpath/tempogate/oidc"
)

// ErrDuplicateInternalState is returned by SaveAuthRequest when an auth
// request with the given internal_state already exists. With 256 bits of
// entropy a collision is not expected; callers may still distinguish it.
var ErrDuplicateInternalState = errors.New("postgres: auth request with this internal_state already exists")

func (s *Store) SaveAuthRequest(ctx context.Context, ar oidc.AuthRequest) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO auth_requests
		   (internal_state, connector_id, client_id, redirect_uri, scope, client_state,
		    code_challenge, code_challenge_method, nonce, created_at, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		ar.InternalState, ar.ConnectorID, ar.ClientID, ar.RedirectURI, ar.Scope, ar.ClientState,
		ar.CodeChallenge, ar.CodeChallengeMethod, ar.Nonce, ar.CreatedAt, ar.ExpiresAt,
	)
	if isUniqueViolation(err) {
		return ErrDuplicateInternalState
	}
	if err != nil {
		return s.fail("save_auth_request", fmt.Errorf("postgres: save auth request: %w", err))
	}
	return nil
}

// ConsumeAuthRequest atomically deletes and returns the pending request keyed
// by internalState. Of concurrent DELETEs on one row, the first to commit
// takes it and the others, re-checking after its lock, find nothing and get
// oidc.ErrAuthRequestNotFound; a replayed state finds the row already gone.
func (s *Store) ConsumeAuthRequest(ctx context.Context, internalState string) (oidc.AuthRequest, error) {
	var ar oidc.AuthRequest
	err := s.pool.QueryRow(ctx,
		`DELETE FROM auth_requests WHERE internal_state = $1
		 RETURNING internal_state, connector_id, client_id, redirect_uri, scope, client_state,
		           code_challenge, code_challenge_method, nonce, created_at, expires_at`,
		internalState,
	).Scan(
		&ar.InternalState, &ar.ConnectorID, &ar.ClientID, &ar.RedirectURI, &ar.Scope, &ar.ClientState,
		&ar.CodeChallenge, &ar.CodeChallengeMethod, &ar.Nonce, &ar.CreatedAt, &ar.ExpiresAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return oidc.AuthRequest{}, oidc.ErrAuthRequestNotFound
	}
	if err != nil {
		return oidc.AuthRequest{}, s.fail("consume_auth_request", fmt.Errorf("postgres: consume auth request: %w", err))
	}
	return ar, nil
}
