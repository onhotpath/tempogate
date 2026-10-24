package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	sqlite3 "modernc.org/sqlite"
	sqlite3lib "modernc.org/sqlite/lib"

	"github.com/onhotpath/tempogate/oidc"
	"github.com/onhotpath/tempogate/state/internal/secret"
)

// ErrDuplicateAuthCode is returned by SaveAuthCode when a code with the same
// value (hash) already exists. With 256 bits of entropy a collision is not expected;
// callers may still distinguish it.
var ErrDuplicateAuthCode = errors.New("sqlite: auth code with this value already exists")

func (s *Store) SaveAuthCode(ctx context.Context, ac oidc.AuthCode) error {
	ctx, op := s.ops.Start(ctx, "save_auth_code")
	defer op.End()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO auth_codes
		   (code_hash, client_id, redirect_uri, connector_id, subject, email, scope,
		    code_challenge, code_challenge_method, nonce, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		secret.Hash(ac.Code), ac.ClientID, ac.RedirectURI, ac.ConnectorID, ac.Subject, ac.Email, ac.Scope,
		ac.CodeChallenge, ac.CodeChallengeMethod, ac.Nonce, ac.CreatedAt, ac.ExpiresAt,
	)
	if err != nil {
		var sqliteErr *sqlite3.Error
		if errors.As(err, &sqliteErr) && sqliteErr.Code() == sqlite3lib.SQLITE_CONSTRAINT_PRIMARYKEY {
			return ErrDuplicateAuthCode
		}
		return op.Fail(fmt.Errorf("sqlite: save auth code: %w", err))
	}
	return nil
}

// ConsumeAuthCode atomically marks the authorization code consumed at the
// given time, matched by its hash (the code itself is never stored), and
// records familyID against it. The UPDATE ... RETURNING is a single
// statement guarded by consumed_at IS NULL, so the max-1-conn store cannot
// hand the same code to two concurrent /token calls: the loser matches no
// live row. The consumed row stays behind as a tombstone until it expires,
// so a replay is told apart from a forgery: it gets the code back, carrying
// the first redemption's family, with oidc.ErrAuthCodeReused. Expiry is the
// caller's concern; an expired code is still returned and then rejected.
func (s *Store) ConsumeAuthCode(ctx context.Context, code, familyID string, at time.Time) (oidc.AuthCode, error) {
	ctx, op := s.ops.Start(ctx, "consume_auth_code")
	defer op.End()
	ac := oidc.AuthCode{Code: code}
	err := s.db.QueryRowContext(ctx,
		`UPDATE auth_codes SET consumed_at = ?, family_id = ?
		 WHERE code_hash = ? AND consumed_at IS NULL
		 RETURNING client_id, redirect_uri, connector_id, subject, email, scope,
		           code_challenge, code_challenge_method, nonce, family_id, created_at, expires_at`,
		at, familyID, secret.Hash(code),
	).Scan(
		&ac.ClientID, &ac.RedirectURI, &ac.ConnectorID, &ac.Subject, &ac.Email, &ac.Scope,
		&ac.CodeChallenge, &ac.CodeChallengeMethod, &ac.Nonce, &ac.FamilyID, &ac.CreatedAt, &ac.ExpiresAt,
	)
	if err == nil {
		return ac, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return oidc.AuthCode{}, op.Fail(fmt.Errorf("sqlite: consume auth code: %w", err))
	}

	err = s.db.QueryRowContext(ctx,
		`SELECT client_id, redirect_uri, connector_id, subject, email, family_id, created_at, expires_at
		 FROM auth_codes WHERE code_hash = ? AND consumed_at IS NOT NULL`,
		secret.Hash(code),
	).Scan(&ac.ClientID, &ac.RedirectURI, &ac.ConnectorID, &ac.Subject, &ac.Email, &ac.FamilyID, &ac.CreatedAt, &ac.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return oidc.AuthCode{}, oidc.ErrAuthCodeNotFound
	}
	if err != nil {
		return oidc.AuthCode{}, op.Fail(fmt.Errorf("sqlite: look up consumed auth code: %w", err))
	}
	return ac, oidc.ErrAuthCodeReused
}
