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
)

// ErrDuplicateDeviceCode is returned by SaveDeviceCode when a row with the
// same device_code or user_code already exists. With 256 bits of entropy on
// device_code and a per-flow regenerate-on-collision loop in the issuer for
// user_code, a real collision is not expected; callers may still distinguish
// it. The error chain is rooted at oidc.ErrDuplicateDeviceCode so consumers
// (the /device_authorization handler in particular) can match via errors.Is
// against the consumer-side sentinel without importing state/sqlite.
var ErrDuplicateDeviceCode = fmt.Errorf("%w: sqlite duplicate", oidc.ErrDuplicateDeviceCode)

// ErrDeviceCodeNotFound is returned by a lookup or consume that finds no row
// — because the row was never written, was already consumed, or was reaped
// by a sweeper. The /token handler maps this to OAuth2 invalid_grant. The
// chain is rooted at oidc.ErrDeviceCodeNotFound for the same consumer-side
// errors.Is reasons as ErrDuplicateDeviceCode.
var ErrDeviceCodeNotFound = fmt.Errorf("%w: sqlite", oidc.ErrDeviceCodeNotFound)

// ErrDeviceCodeNotPending is returned by Approve / Deny when the targeted
// row exists but is no longer in the pending state — its approved_at or
// denied_at is already stamped. The verification handler maps this to
// "already_decided" so the user cannot flip a Deny to an Approve by
// re-submitting the form. Chain rooted at oidc.ErrDeviceCodeNotPending.
var ErrDeviceCodeNotPending = fmt.Errorf("%w: sqlite", oidc.ErrDeviceCodeNotPending)

func (s *Store) SaveDeviceCode(ctx context.Context, dc oidc.DeviceCode) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO device_codes
		   (device_code, user_code, client_id, scope, email,
		    approved_at, denied_at, last_polled_at, interval_seconds,
		    created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		dc.Code, dc.UserCode, dc.ClientID, dc.Scope, nullString(dc.Email),
		nullTime(dc.ApprovedAt), nullTime(dc.DeniedAt), nullTime(dc.LastPolledAt),
		dc.IntervalSeconds, dc.CreatedAt, dc.ExpiresAt,
	)
	if err != nil {
		var sqliteErr *sqlite3.Error
		if errors.As(err, &sqliteErr) {
			switch sqliteErr.Code() {
			case sqlite3lib.SQLITE_CONSTRAINT_PRIMARYKEY, sqlite3lib.SQLITE_CONSTRAINT_UNIQUE:
				return fmt.Errorf("%w: %s", ErrDuplicateDeviceCode, dc.Code)
			}
		}
		return fmt.Errorf("sqlite: save device code: %w", err)
	}
	return nil
}

func (s *Store) LookupDeviceCodeByDeviceCode(ctx context.Context, deviceCode string) (oidc.DeviceCode, error) {
	return s.lookupDeviceCode(ctx, "device_code", deviceCode)
}

// LookupDeviceCodeByUserCode resolves the verification-page path's row.
// Caller is responsible for normalising the user_code (uppercase, strip
// dashes) before calling; the column is stored already normalised so the
// lookup is a plain UNIQUE-index probe.
func (s *Store) LookupDeviceCodeByUserCode(ctx context.Context, userCode string) (oidc.DeviceCode, error) {
	return s.lookupDeviceCode(ctx, "user_code", userCode)
}

func (s *Store) lookupDeviceCode(ctx context.Context, column, value string) (oidc.DeviceCode, error) {
	var (
		dc           oidc.DeviceCode
		email        sql.NullString
		approvedAt   sql.NullTime
		deniedAt     sql.NullTime
		lastPolledAt sql.NullTime
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT device_code, user_code, client_id, scope, email,
		        approved_at, denied_at, last_polled_at, interval_seconds,
		        created_at, expires_at
		 FROM device_codes
		 WHERE `+column+` = ?`,
		value,
	).Scan(
		&dc.Code, &dc.UserCode, &dc.ClientID, &dc.Scope, &email,
		&approvedAt, &deniedAt, &lastPolledAt, &dc.IntervalSeconds,
		&dc.CreatedAt, &dc.ExpiresAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return oidc.DeviceCode{}, fmt.Errorf("%w: %s", ErrDeviceCodeNotFound, value)
	}
	if err != nil {
		return oidc.DeviceCode{}, fmt.Errorf("sqlite: lookup device code by %s: %w", column, err)
	}
	if email.Valid {
		dc.Email = email.String
	}
	dc.ApprovedAt = nullableTime(approvedAt)
	dc.DeniedAt = nullableTime(deniedAt)
	dc.LastPolledAt = nullableTime(lastPolledAt)
	return dc, nil
}

// TouchDeviceCodePoll records the latest poll timestamp and, when
// bumpInterval is true, raises the server-tracked minimum-poll-interval by
// the RFC 8628 §3.5 increment (+5 seconds). The /token handler calls this on
// every device-code poll: it sets bumpInterval only when the poll arrived
// inside the current interval window (the slow_down path), so well-behaved
// clients never pay the penalty.
func (s *Store) TouchDeviceCodePoll(ctx context.Context, deviceCode string, now time.Time, bumpInterval bool) error {
	stmt := `UPDATE device_codes SET last_polled_at = ? WHERE device_code = ?`
	args := []any{now, deviceCode}
	if bumpInterval {
		stmt = `UPDATE device_codes
		        SET last_polled_at = ?, interval_seconds = interval_seconds + 5
		        WHERE device_code = ?`
	}
	res, err := s.db.ExecContext(ctx, stmt, args...)
	if err != nil {
		return fmt.Errorf("sqlite: touch device code poll: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("sqlite: touch device code poll rows: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("%w: %s", ErrDeviceCodeNotFound, deviceCode)
	}
	return nil
}

// ApproveDeviceCode atomically stamps the row as approved by `email` only
// when it is still pending (both approved_at and denied_at NULL). Zero rows
// affected ⇒ ErrDeviceCodeNotPending, which the verification handler maps to
// "already_decided" — a second click on Approve, an Approve after Deny, or a
// completely unknown user_code all collapse to the same outward error so the
// UI cannot be coaxed into revealing whether a user_code is in use.
func (s *Store) ApproveDeviceCode(ctx context.Context, userCode, email string, now time.Time) error {
	return s.decideDeviceCode(ctx,
		`UPDATE device_codes
		 SET approved_at = ?, email = ?
		 WHERE user_code = ?
		   AND approved_at IS NULL
		   AND denied_at IS NULL`,
		[]any{now, email, userCode},
		userCode,
	)
}

func (s *Store) DenyDeviceCode(ctx context.Context, userCode string, now time.Time) error {
	return s.decideDeviceCode(ctx,
		`UPDATE device_codes
		 SET denied_at = ?
		 WHERE user_code = ?
		   AND approved_at IS NULL
		   AND denied_at IS NULL`,
		[]any{now, userCode},
		userCode,
	)
}

func (s *Store) decideDeviceCode(ctx context.Context, stmt string, args []any, userCode string) error {
	res, err := s.db.ExecContext(ctx, stmt, args...)
	if err != nil {
		return fmt.Errorf("sqlite: decide device code: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("sqlite: decide device code rows: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("%w: %s", ErrDeviceCodeNotPending, userCode)
	}
	return nil
}

// ConsumeDeviceCode atomically deletes and returns the row. Mirrors
// ConsumeAuthCode: the DELETE ... RETURNING is a single statement, so the
// max-1-conn store cannot hand the same code to two concurrent /token polls
// — the loser sees zero rows and gets ErrDeviceCodeNotFound. Called only on
// the final token-mint path, after an Approve has stamped the row.
func (s *Store) ConsumeDeviceCode(ctx context.Context, deviceCode string) (oidc.DeviceCode, error) {
	var (
		dc           oidc.DeviceCode
		email        sql.NullString
		approvedAt   sql.NullTime
		deniedAt     sql.NullTime
		lastPolledAt sql.NullTime
	)
	err := s.db.QueryRowContext(ctx,
		`DELETE FROM device_codes WHERE device_code = ?
		 RETURNING device_code, user_code, client_id, scope, email,
		           approved_at, denied_at, last_polled_at, interval_seconds,
		           created_at, expires_at`,
		deviceCode,
	).Scan(
		&dc.Code, &dc.UserCode, &dc.ClientID, &dc.Scope, &email,
		&approvedAt, &deniedAt, &lastPolledAt, &dc.IntervalSeconds,
		&dc.CreatedAt, &dc.ExpiresAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return oidc.DeviceCode{}, fmt.Errorf("%w: %s", ErrDeviceCodeNotFound, deviceCode)
	}
	if err != nil {
		return oidc.DeviceCode{}, fmt.Errorf("sqlite: consume device code: %w", err)
	}
	if email.Valid {
		dc.Email = email.String
	}
	dc.ApprovedAt = nullableTime(approvedAt)
	dc.DeniedAt = nullableTime(deniedAt)
	dc.LastPolledAt = nullableTime(lastPolledAt)
	return dc, nil
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return *t
}

func nullableTime(n sql.NullTime) *time.Time {
	if !n.Valid {
		return nil
	}
	t := n.Time
	return &t
}
