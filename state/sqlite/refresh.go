package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	sqlite3 "modernc.org/sqlite"
	sqlite3lib "modernc.org/sqlite/lib"

	"github.com/onhotpath/tempogate/admin"
	"github.com/onhotpath/tempogate/oidc"
	"github.com/onhotpath/tempogate/state/internal/instrument"
	"github.com/onhotpath/tempogate/state/internal/secret"
)

// ErrDuplicateRefreshToken is returned by SaveRefresh when a token with the
// same value (hash) already exists. With 256 bits of entropy a collision is
// not expected; callers may still distinguish it.
var ErrDuplicateRefreshToken = errors.New("sqlite: refresh token with this value already exists")

// refreshColumns is the insert list. Reads return refreshFields, without the
// hash: the token itself is never stored (migration 0012), so the caller
// passes it in and gets it back on the returned Refresh.
const (
	refreshFields  = `jti, client_id, connector_id, subject, email, family_id, auth_time, created_at, expires_at`
	refreshColumns = `token_hash, ` + refreshFields
)

// SaveRefresh inserts r unless its family has been revoked. The check and the
// insert are one statement, so a rotation that consumed its parent before a
// revocation cannot persist the child after it (oidc.ErrRefreshFamilyRevoked).
func (s *Store) SaveRefresh(ctx context.Context, r oidc.Refresh) error {
	ctx, op := s.ops.Start(ctx, "save_refresh")
	defer op.End()
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO refresh_tokens (`+refreshColumns+`)
		 SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
		 WHERE NOT EXISTS (
		     SELECT 1 FROM refresh_tokens WHERE family_id = ? AND revoked_at IS NOT NULL
		 )`,
		secret.Hash(r.Token), r.JTI, r.ClientID, r.ConnectorID, r.Subject, r.Email, r.FamilyID, r.AuthTime, r.CreatedAt, r.ExpiresAt,
		r.FamilyID,
	)
	if err != nil {
		var sqliteErr *sqlite3.Error
		if errors.As(err, &sqliteErr) && sqliteErr.Code() == sqlite3lib.SQLITE_CONSTRAINT_PRIMARYKEY {
			return ErrDuplicateRefreshToken
		}
		return op.Fail(fmt.Errorf("sqlite: save refresh token: %w", err))
	}
	n, err := res.RowsAffected()
	if err != nil {
		return op.Fail(fmt.Errorf("sqlite: save refresh token: %w", err))
	}
	if n == 0 {
		return fmt.Errorf("%w: %s", oidc.ErrRefreshFamilyRevoked, r.FamilyID)
	}
	return nil
}

// ConsumeRefresh marks the live refresh token issued to clientID consumed and
// returns it. The conditional UPDATE ... RETURNING is a single statement, so
// of any number of concurrent presentations exactly one sees the row live;
// the others find the tombstone it leaves and are reported as reuse, which
// is what a duplicate presentation of a rotated token is (RFC 9700
// §4.14.2). The client_id predicate means a token presented by another
// client, live or consumed, is reported missing and left intact.
func (s *Store) ConsumeRefresh(ctx context.Context, token, clientID string, at time.Time) (oidc.Refresh, error) {
	ctx, op := s.ops.Start(ctx, "consume_refresh")
	defer op.End()
	hash := secret.Hash(token)
	r, err := scanRefresh(token, s.db.QueryRowContext(ctx,
		`UPDATE refresh_tokens SET consumed_at = ?
		 WHERE token_hash = ? AND client_id = ? AND consumed_at IS NULL AND revoked_at IS NULL
		 RETURNING `+refreshFields,
		at, hash, clientID,
	))
	if err == nil {
		return r, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return oidc.Refresh{}, op.Fail(fmt.Errorf("sqlite: consume refresh token: %w", err))
	}

	r, err = scanRefresh(token, s.db.QueryRowContext(ctx,
		`SELECT `+refreshFields+` FROM refresh_tokens
		 WHERE token_hash = ? AND client_id = ? AND consumed_at IS NOT NULL`,
		hash, clientID,
	))
	if errors.Is(err, sql.ErrNoRows) {
		return oidc.Refresh{}, oidc.ErrRefreshNotFound
	}
	if err != nil {
		return oidc.Refresh{}, op.Fail(fmt.Errorf("sqlite: look up consumed refresh token: %w", err))
	}
	return r, oidc.ErrRefreshReused
}

// RevokeRefreshFamily marks every row of the family revoked, tombstones
// included (so SaveRefresh refuses further rotations), and reports how many
// live tokens it ended. A family with no rows at all wraps
// admin.ErrSessionNotFound, so an operator's mistyped id is not reported as
// a successful revoke; an already-revoked family is a zero count.
func (s *Store) RevokeRefreshFamily(ctx context.Context, familyID string, at time.Time) (int, error) {
	ctx, op := s.ops.Start(ctx, "revoke_refresh")
	defer op.End()
	n, err := s.revokeRefresh(ctx, op, `family_id = ?`, at, familyID)
	if err != nil || n > 0 {
		return n, err
	}
	var exists bool
	if err := s.db.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM refresh_tokens WHERE family_id = ?)`, familyID,
	).Scan(&exists); err != nil {
		return 0, op.Fail(fmt.Errorf("sqlite: look up refresh family: %w", err))
	}
	if !exists {
		return 0, fmt.Errorf("%w: %s", admin.ErrSessionNotFound, familyID)
	}
	return 0, nil
}

// RevokeRefreshByEmail revokes every family belonging to email, matched
// case-insensitively, and reports how many live sessions it ended.
func (s *Store) RevokeRefreshByEmail(ctx context.Context, email string, at time.Time) (int, error) {
	ctx, op := s.ops.Start(ctx, "revoke_refresh")
	defer op.End()
	return s.revokeRefresh(ctx, op, `lower(email) = lower(?)`, at, email)
}

// RevokeRefreshBySubject revokes every family of the upstream subject at
// connectorID, matched exactly (a sub is an opaque, case-sensitive id), and
// reports how many live sessions it ended. Unlike email, the subject
// survives a rename of the account, so it is the selector that reliably ends
// one person's sessions.
func (s *Store) RevokeRefreshBySubject(ctx context.Context, connectorID, subject string, at time.Time) (int, error) {
	ctx, op := s.ops.Start(ctx, "revoke_refresh")
	defer op.End()
	return s.revokeRefresh(ctx, op, `connector_id = ? AND subject = ?`, at, connectorID, subject)
}

// revokeRefresh runs as part of its caller's revoke_refresh operation.
func (s *Store) revokeRefresh(ctx context.Context, op *instrument.Op, where string, at time.Time, args ...any) (int, error) {
	// #nosec G202 -- where is one of the constant predicates above, never input.
	rows, err := s.db.QueryContext(ctx,
		`UPDATE refresh_tokens SET revoked_at = ?
		 WHERE `+where+` AND revoked_at IS NULL
		 RETURNING consumed_at IS NULL`,
		append([]any{at}, args...)...,
	)
	if err != nil {
		return 0, op.Fail(fmt.Errorf("sqlite: revoke refresh tokens: %w", err))
	}
	defer func() { _ = rows.Close() }()

	live := 0
	for rows.Next() {
		var wasLive bool
		if err := rows.Scan(&wasLive); err != nil {
			return 0, op.Fail(fmt.Errorf("sqlite: scan revoked refresh token: %w", err))
		}
		if wasLive {
			live++
		}
	}
	if err := rows.Err(); err != nil {
		return 0, op.Fail(fmt.Errorf("sqlite: revoke refresh tokens: %w", err))
	}
	return live, nil
}

// RefreshSession describes one live refresh-token family for operators. It
// deliberately carries no token value.
type RefreshSession struct {
	FamilyID    string
	ClientID    string
	ConnectorID string
	Subject     string
	Email       string
	AuthTime    time.Time
	RotatedAt   time.Time // when the live token was minted
	ExpiresAt   time.Time
}

// RefreshSessionFilter narrows ListRefreshSessions. Empty fields do not
// filter; Email matches case-insensitively, ConnectorID and Subject exactly.
type RefreshSessionFilter struct {
	Email       string
	ConnectorID string
	Subject     string
}

// ListRefreshSessions returns the live sessions (one per family: its
// unconsumed, unrevoked, unexpired token) matching f. Expiry is filtered
// against now in Go rather than SQL because the driver's timestamp text does
// not order lexically across writers.
func (s *Store) ListRefreshSessions(ctx context.Context, f RefreshSessionFilter, now time.Time) ([]RefreshSession, error) {
	ctx, op := s.ops.Start(ctx, "list_refresh_sessions")
	defer op.End()
	rows, err := s.db.QueryContext(ctx,
		`SELECT family_id, client_id, connector_id, subject, email, auth_time, created_at, expires_at
		 FROM refresh_tokens
		 WHERE consumed_at IS NULL AND revoked_at IS NULL
		   AND (? = '' OR lower(email) = lower(?))
		   AND (? = '' OR connector_id = ?)
		   AND (? = '' OR subject = ?)
		 ORDER BY email, auth_time`,
		f.Email, f.Email, f.ConnectorID, f.ConnectorID, f.Subject, f.Subject,
	)
	if err != nil {
		return nil, op.Fail(fmt.Errorf("sqlite: list refresh sessions: %w", err))
	}
	defer func() { _ = rows.Close() }()

	var out []RefreshSession
	for rows.Next() {
		var rs RefreshSession
		if err := rows.Scan(&rs.FamilyID, &rs.ClientID, &rs.ConnectorID, &rs.Subject, &rs.Email, &rs.AuthTime, &rs.RotatedAt, &rs.ExpiresAt); err != nil {
			return nil, op.Fail(fmt.Errorf("sqlite: scan refresh session: %w", err))
		}
		if now.Before(rs.ExpiresAt) {
			out = append(out, rs)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, op.Fail(fmt.Errorf("sqlite: list refresh sessions: %w", err))
	}
	return out, nil
}

func scanRefresh(token string, row *sql.Row) (oidc.Refresh, error) {
	r := oidc.Refresh{Token: token}
	err := row.Scan(&r.JTI, &r.ClientID, &r.ConnectorID, &r.Subject, &r.Email, &r.FamilyID, &r.AuthTime, &r.CreatedAt, &r.ExpiresAt)
	return r, err
}
