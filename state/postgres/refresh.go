package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/onhotpath/tempogate/admin"
	"github.com/onhotpath/tempogate/oidc"
	"github.com/onhotpath/tempogate/state/internal/secret"
)

// ErrDuplicateRefreshToken is returned by SaveRefresh when a token with the
// same value (hash) already exists. With 256 bits of entropy a collision is
// not expected; callers may still distinguish it.
var ErrDuplicateRefreshToken = errors.New("postgres: refresh token with this value already exists")

// refreshColumns is the insert list. Reads return refreshFields, without the
// hash: the token itself is never stored, so the caller passes it in and
// gets it back on the returned Refresh.
const (
	refreshFields  = `jti, client_id, subject, email, family_id, auth_time, created_at, expires_at`
	refreshColumns = `token_hash, ` + refreshFields
)

// emailMatches compares an email column with the $1 parameter the way
// SQLite's lower() does: ASCII letters fold, every other byte must match.
// lower() under the "C" collation is ASCII-only in every supported major.
const emailMatches = `lower(email COLLATE "C") = lower($1::text COLLATE "C")`

// SaveRefresh inserts r unless its family has been revoked. It creates the
// family's refresh_families row if needed and holds it FOR SHARE while it
// inserts, and every revocation updates that row before it revokes tokens.
// So a revocation either commits first, and the rotation sees it and gets
// oidc.ErrRefreshFamilyRevoked, or waits for the rotation to commit and then
// revokes the new child with the rest of the family.
func (s *Store) SaveRefresh(ctx context.Context, r oidc.Refresh) error {
	errRevoked := fmt.Errorf("%w: %s", oidc.ErrRefreshFamilyRevoked, r.FamilyID)
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		revoked, err := lockFamily(ctx, tx, r.FamilyID)
		if err != nil {
			return err
		}
		if revoked {
			return errRevoked
		}
		_, err = tx.Exec(ctx,
			`INSERT INTO refresh_tokens (`+refreshColumns+`) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			secret.Hash(r.Token), r.JTI, r.ClientID, r.Subject, r.Email, r.FamilyID, r.AuthTime, r.CreatedAt, r.ExpiresAt,
		)
		return err
	})
	switch {
	case err == nil:
		return nil
	case errors.Is(err, errRevoked):
		return err
	case isUniqueViolation(err):
		return ErrDuplicateRefreshToken
	default:
		return s.fail("save_refresh", fmt.Errorf("postgres: save refresh token: %w", err))
	}
}

// lockFamily takes familyID's refresh_families row FOR SHARE, creating it
// for a new sign-in, and reports whether the family is revoked. The lock
// waits for a revocation in flight and makes a later one wait for this
// transaction.
func lockFamily(ctx context.Context, tx pgx.Tx, familyID string) (bool, error) {
	for {
		var revoked bool
		err := tx.QueryRow(ctx,
			`SELECT revoked_at IS NOT NULL FROM refresh_families WHERE family_id = $1 FOR SHARE`,
			familyID,
		).Scan(&revoked)
		if !errors.Is(err, pgx.ErrNoRows) {
			return revoked, err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO refresh_families (family_id) VALUES ($1) ON CONFLICT (family_id) DO NOTHING`,
			familyID,
		); err != nil {
			return false, err
		}
	}
}

// ConsumeRefresh marks the live refresh token issued to clientID consumed and
// returns it. Concurrent UPDATEs of one row queue on its lock and re-check
// the predicate, so exactly one presentation sees the row live; the others
// find the tombstone it leaves and are reported as reuse (RFC 9700
// §4.14.2). The client_id predicate means a token presented by another
// client, live or consumed, is reported missing and left intact.
func (s *Store) ConsumeRefresh(ctx context.Context, token, clientID string, at time.Time) (oidc.Refresh, error) {
	hash := secret.Hash(token)
	r, err := scanRefresh(token, s.pool.QueryRow(ctx,
		`UPDATE refresh_tokens SET consumed_at = $1
		 WHERE token_hash = $2 AND client_id = $3 AND consumed_at IS NULL AND revoked_at IS NULL
		 RETURNING `+refreshFields,
		at, hash, clientID,
	))
	if err == nil {
		return r, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return oidc.Refresh{}, s.fail("consume_refresh", fmt.Errorf("postgres: consume refresh token: %w", err))
	}

	r, err = scanRefresh(token, s.pool.QueryRow(ctx,
		`SELECT `+refreshFields+` FROM refresh_tokens
		 WHERE token_hash = $1 AND client_id = $2 AND consumed_at IS NOT NULL`,
		hash, clientID,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return oidc.Refresh{}, oidc.ErrRefreshNotFound
	}
	if err != nil {
		return oidc.Refresh{}, s.fail("consume_refresh", fmt.Errorf("postgres: look up consumed refresh token: %w", err))
	}
	return r, oidc.ErrRefreshReused
}

// RevokeRefreshFamily marks the family and every row of it revoked,
// tombstones included, and reports how many live tokens it ended. A family
// with no rows at all wraps admin.ErrSessionNotFound, so an operator's
// mistyped id is not reported as a successful revoke; an already-revoked
// family keeps its first revoked_at and is a zero count.
func (s *Store) RevokeRefreshFamily(ctx context.Context, familyID string, at time.Time) (int, error) {
	errUnknown := fmt.Errorf("%w: %s", admin.ErrSessionNotFound, familyID)
	var live int
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE refresh_families SET revoked_at = coalesce(revoked_at, $2) WHERE family_id = $1`,
			familyID, at,
		)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return errUnknown
		}
		live, err = revokeTokens(ctx, tx, []string{familyID}, at)
		return err
	})
	if errors.Is(err, errUnknown) {
		return 0, err
	}
	if err != nil {
		return 0, s.fail("revoke_refresh", fmt.Errorf("postgres: revoke refresh tokens: %w", err))
	}
	return live, nil
}

// RevokeRefreshByEmail revokes every family belonging to email, matched
// case-insensitively for ASCII letters (emailMatches), and reports how many
// live sessions it ended.
func (s *Store) RevokeRefreshByEmail(ctx context.Context, email string, at time.Time) (int, error) {
	return s.revokeFamiliesWhere(ctx, emailMatches, email, at)
}

// RevokeRefreshBySubject revokes every family of the subject, matched
// exactly, and reports how many live sessions it ended.
func (s *Store) RevokeRefreshBySubject(ctx context.Context, subject string, at time.Time) (int, error) {
	return s.revokeFamiliesWhere(ctx, `subject = $1`, subject, at)
}

// revokeFamiliesWhere revokes the families with a token matching where. It
// locks their refresh_families rows in family_id order, so two revocations
// over overlapping families cannot deadlock, then revokes their tokens.
func (s *Store) revokeFamiliesWhere(ctx context.Context, where, arg string, at time.Time) (int, error) {
	var live int
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		// #nosec G202 -- where is one of the constant predicates above, never input.
		rows, err := tx.Query(ctx,
			`WITH locked AS (
			     SELECT family_id FROM refresh_families
			     WHERE family_id IN (SELECT family_id FROM refresh_tokens WHERE `+where+`)
			     ORDER BY family_id
			     FOR UPDATE
			 )
			 UPDATE refresh_families f SET revoked_at = coalesce(f.revoked_at, $2)
			 FROM locked WHERE f.family_id = locked.family_id
			 RETURNING f.family_id`,
			arg, at,
		)
		if err != nil {
			return err
		}
		families, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return err
		}
		live, err = revokeTokens(ctx, tx, families, at)
		return err
	})
	if err != nil {
		return 0, s.fail("revoke_refresh", fmt.Errorf("postgres: revoke refresh tokens: %w", err))
	}
	return live, nil
}

// revokeTokens stamps every unrevoked token of families and counts those
// that were live (not yet consumed).
func revokeTokens(ctx context.Context, tx pgx.Tx, families []string, at time.Time) (int, error) {
	var live int
	err := tx.QueryRow(ctx,
		`WITH revoked AS (
		     UPDATE refresh_tokens SET revoked_at = $2
		     WHERE family_id = ANY($1) AND revoked_at IS NULL
		     RETURNING consumed_at
		 )
		 SELECT count(*) FILTER (WHERE consumed_at IS NULL) FROM revoked`,
		families, at,
	).Scan(&live)
	return live, err
}

// ListRefreshSessions returns the live sessions (one per family: its
// unconsumed, unrevoked, unexpired token) matching f, by email (bytewise,
// like SQLite) then auth_time.
func (s *Store) ListRefreshSessions(ctx context.Context, f admin.SessionFilter, now time.Time) ([]admin.Session, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT family_id, client_id, subject, email, auth_time, created_at, expires_at
		 FROM refresh_tokens
		 WHERE consumed_at IS NULL AND revoked_at IS NULL AND expires_at > $3
		   AND ($1::text = '' OR `+emailMatches+`)
		   AND ($2::text = '' OR subject = $2)
		 ORDER BY email COLLATE "C", auth_time`,
		f.Email, f.Subject, now,
	)
	if err != nil {
		return nil, s.fail("list_refresh_sessions", fmt.Errorf("postgres: list refresh sessions: %w", err))
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (admin.Session, error) {
		var rs admin.Session
		err := r.Scan(&rs.FamilyID, &rs.ClientID, &rs.Subject, &rs.Email, &rs.AuthTime, &rs.RotatedAt, &rs.ExpiresAt)
		return rs, err
	})
	if err != nil {
		return nil, s.fail("list_refresh_sessions", fmt.Errorf("postgres: list refresh sessions: %w", err))
	}
	return out, nil
}

func scanRefresh(token string, row pgx.Row) (oidc.Refresh, error) {
	r := oidc.Refresh{Token: token}
	err := row.Scan(&r.JTI, &r.ClientID, &r.Subject, &r.Email, &r.FamilyID, &r.AuthTime, &r.CreatedAt, &r.ExpiresAt)
	return r, err
}
