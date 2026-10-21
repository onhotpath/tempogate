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

// ErrDuplicateBrowserSession is returned by SaveBrowserSession when a row
// with the same sid already exists. With 256 bits of entropy a collision is
// not expected; callers may still distinguish it.
var ErrDuplicateBrowserSession = errors.New("sqlite: browser session with this sid already exists")

func (s *Store) SaveBrowserSession(ctx context.Context, bs oidc.BrowserSession) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO browser_sessions (sid_hash, subject, email, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?)`,
		secretHash(bs.SID), bs.Subject, bs.Email, bs.CreatedAt, bs.ExpiresAt,
	)
	if err != nil {
		var sqliteErr *sqlite3.Error
		if errors.As(err, &sqliteErr) && sqliteErr.Code() == sqlite3lib.SQLITE_CONSTRAINT_PRIMARYKEY {
			return ErrDuplicateBrowserSession
		}
		return fmt.Errorf("sqlite: save browser session: %w", err)
	}
	return nil
}

// LookupBrowserSession finds the session by the hash of sid (the sid itself
// is never stored) and echoes sid back on the result.
func (s *Store) LookupBrowserSession(ctx context.Context, sid string) (oidc.BrowserSession, error) {
	bs := oidc.BrowserSession{SID: sid}
	err := s.db.QueryRowContext(ctx,
		`SELECT subject, email, created_at, expires_at
		 FROM browser_sessions
		 WHERE sid_hash = ?`,
		secretHash(sid),
	).Scan(&bs.Subject, &bs.Email, &bs.CreatedAt, &bs.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return oidc.BrowserSession{}, oidc.ErrBrowserSessionNotFound
	}
	if err != nil {
		return oidc.BrowserSession{}, fmt.Errorf("sqlite: lookup browser session: %w", err)
	}
	return bs, nil
}

// DeleteBrowserSession is best-effort: an unknown sid is a no-op rather than
// an error, so sign-out and forced-revocation paths can fan out to the store
// without re-checking existence.
func (s *Store) DeleteBrowserSession(ctx context.Context, sid string) error {
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM browser_sessions WHERE sid_hash = ?`, secretHash(sid),
	); err != nil {
		return fmt.Errorf("sqlite: delete browser session: %w", err)
	}
	return nil
}
