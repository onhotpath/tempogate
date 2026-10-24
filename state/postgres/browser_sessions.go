package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/onhotpath/tempogate/oidc"
	"github.com/onhotpath/tempogate/state/internal/secret"
)

// ErrDuplicateBrowserSession is returned by SaveBrowserSession when a row
// with the same sid already exists. With 256 bits of entropy a collision is
// not expected; callers may still distinguish it.
var ErrDuplicateBrowserSession = errors.New("postgres: browser session with this sid already exists")

func (s *Store) SaveBrowserSession(ctx context.Context, bs oidc.BrowserSession) error {
	ctx, op := s.ops.Start(ctx, "save_browser_session")
	defer op.End()
	_, err := s.pool.Exec(ctx,
		`INSERT INTO browser_sessions (sid_hash, connector_id, subject, email, created_at, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		secret.Hash(bs.SID), bs.ConnectorID, bs.Subject, bs.Email, bs.CreatedAt, bs.ExpiresAt,
	)
	if isUniqueViolation(err) {
		return ErrDuplicateBrowserSession
	}
	if err != nil {
		return op.Fail(fmt.Errorf("postgres: save browser session: %w", err))
	}
	return nil
}

// LookupBrowserSession finds the session by the hash of sid (the sid itself
// is never stored) and echoes sid back on the result.
func (s *Store) LookupBrowserSession(ctx context.Context, sid string) (oidc.BrowserSession, error) {
	ctx, op := s.ops.Start(ctx, "lookup_browser_session")
	defer op.End()
	bs := oidc.BrowserSession{SID: sid}
	err := s.pool.QueryRow(ctx,
		`SELECT connector_id, subject, email, created_at, expires_at
		 FROM browser_sessions
		 WHERE sid_hash = $1`,
		secret.Hash(sid),
	).Scan(&bs.ConnectorID, &bs.Subject, &bs.Email, &bs.CreatedAt, &bs.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return oidc.BrowserSession{}, oidc.ErrBrowserSessionNotFound
	}
	if err != nil {
		return oidc.BrowserSession{}, op.Fail(fmt.Errorf("postgres: lookup browser session: %w", err))
	}
	return bs, nil
}

// DeleteBrowserSession is best-effort: an unknown sid is a no-op rather than
// an error, so sign-out and forced-revocation paths can fan out to the store
// without re-checking existence.
func (s *Store) DeleteBrowserSession(ctx context.Context, sid string) error {
	ctx, op := s.ops.Start(ctx, "delete_browser_session")
	defer op.End()
	if _, err := s.pool.Exec(ctx,
		`DELETE FROM browser_sessions WHERE sid_hash = $1`, secret.Hash(sid),
	); err != nil {
		return op.Fail(fmt.Errorf("postgres: delete browser session: %w", err))
	}
	return nil
}
