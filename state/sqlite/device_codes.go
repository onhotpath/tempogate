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

// ErrDuplicateDeviceCode is returned by SaveDeviceCode when a row with the
// same device_code or user_code already exists. With 256 bits of entropy on
// device_code and a per-flow regenerate-on-collision loop in the issuer for
// user_code, a real collision is not expected; callers may still distinguish
// it. The error chain is rooted at oidc.ErrDuplicateDeviceCode so consumers
// (the /device_authorization handler in particular) can match via errors.Is
// against the consumer-side sentinel without importing state/sqlite.
var ErrDuplicateDeviceCode = fmt.Errorf("%w: sqlite duplicate", oidc.ErrDuplicateDeviceCode)

// ErrDeviceCodeNotFound is returned by a lookup or consume that finds no row,
// because the row was never written, was already consumed, or was deleted
// by the expiry reaper (reaper.go). The /token handler maps this to OAuth2 invalid_grant. The
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
		   (device_code_hash, user_code, client_id, scope, connector_id, subject, email,
		    approved_at, denied_at, last_polled_at, interval_seconds,
		    created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		secret.Hash(dc.Code), dc.UserCode, dc.ClientID, dc.Scope, nullString(dc.ConnectorID), nullString(dc.Subject), nullString(dc.Email),
		nullTime(dc.ApprovedAt), nullTime(dc.DeniedAt), nullTime(dc.LastPolledAt),
		dc.IntervalSeconds, dc.CreatedAt, dc.ExpiresAt,
	)
	if err != nil {
		var sqliteErr *sqlite3.Error
		if errors.As(err, &sqliteErr) {
			switch sqliteErr.Code() {
			case sqlite3lib.SQLITE_CONSTRAINT_PRIMARYKEY, sqlite3lib.SQLITE_CONSTRAINT_UNIQUE:
				return ErrDuplicateDeviceCode
			}
		}
		return s.fail("save_device_code", fmt.Errorf("sqlite: save device code: %w", err))
	}
	return nil
}

func (s *Store) LookupDeviceCodeByDeviceCode(ctx context.Context, deviceCode string) (oidc.DeviceCode, error) {
	dc, err := s.lookupDeviceCode(ctx, "device_code_hash", secret.Hash(deviceCode))
	if err != nil {
		return oidc.DeviceCode{}, err
	}
	dc.Code = deviceCode
	return dc, nil
}

// LookupDeviceCodeByUserCode resolves the verification-page path's row.
// Caller is responsible for normalising the user_code (uppercase, strip
// dashes) before calling; the column is stored already normalised so the
// lookup is a plain UNIQUE-index probe. The result's Code is empty: only
// the device code's hash is stored, and this path never needs it.
func (s *Store) LookupDeviceCodeByUserCode(ctx context.Context, userCode string) (oidc.DeviceCode, error) {
	return s.lookupDeviceCode(ctx, "user_code", userCode)
}

func (s *Store) lookupDeviceCode(ctx context.Context, column, value string) (oidc.DeviceCode, error) {
	var (
		dc           oidc.DeviceCode
		connectorID  sql.NullString
		subject      sql.NullString
		email        sql.NullString
		approvedAt   sql.NullTime
		deniedAt     sql.NullTime
		lastPolledAt sql.NullTime
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT user_code, client_id, scope, connector_id, subject, email,
		        approved_at, denied_at, last_polled_at, interval_seconds,
		        created_at, expires_at
		 FROM device_codes
		 WHERE `+column+` = ?`,
		value,
	).Scan(
		&dc.UserCode, &dc.ClientID, &dc.Scope, &connectorID, &subject, &email,
		&approvedAt, &deniedAt, &lastPolledAt, &dc.IntervalSeconds,
		&dc.CreatedAt, &dc.ExpiresAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return oidc.DeviceCode{}, ErrDeviceCodeNotFound
	}
	if err != nil {
		return oidc.DeviceCode{}, s.fail("lookup_device_code", fmt.Errorf("sqlite: lookup device code by %s: %w", column, err))
	}
	dc.ConnectorID = connectorID.String
	dc.Subject = subject.String
	dc.Email = email.String
	dc.ApprovedAt = nullableTime(approvedAt)
	dc.DeniedAt = nullableTime(deniedAt)
	dc.LastPolledAt = nullableTime(lastPolledAt)
	return dc, nil
}

// PollDeviceCode records a /token poll and enforces the RFC 8628 §3.5
// minimum interval in one step, so parallel polls cannot all pass as
// well-paced. A poll inside the stored interval of the previous one is
// slow_down: it bumps interval_seconds by 5 and reports true. Otherwise it
// claims the row by compare-and-swap on the exact stored last_polled_at, so
// of N concurrent well-paced-looking polls exactly one wins and the rest
// are slow_down. The interval is judged in Go because timestamps are stored
// as Go time strings that SQLite's date functions cannot read.
func (s *Store) PollDeviceCode(ctx context.Context, deviceCode string, now time.Time) (bool, error) {
	hash := secret.Hash(deviceCode)
	var (
		lastPolled    sql.NullTime
		lastPolledRaw sql.NullString
		interval      int
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT last_polled_at, CAST(last_polled_at AS TEXT), interval_seconds
		 FROM device_codes WHERE device_code_hash = ?`,
		hash,
	).Scan(&lastPolled, &lastPolledRaw, &interval)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrDeviceCodeNotFound
	}
	if err != nil {
		return false, s.fail("poll_device_code", fmt.Errorf("sqlite: poll device code: %w", err))
	}

	if !lastPolled.Valid || now.Sub(lastPolled.Time) >= time.Duration(interval)*time.Second {
		var prev any
		if lastPolledRaw.Valid {
			prev = lastPolledRaw.String
		}
		res, err := s.db.ExecContext(ctx,
			`UPDATE device_codes SET last_polled_at = ?
			 WHERE device_code_hash = ? AND last_polled_at IS ?`,
			now, hash, prev,
		)
		if err != nil {
			return false, s.fail("poll_device_code", fmt.Errorf("sqlite: poll device code: %w", err))
		}
		if n, err := res.RowsAffected(); err != nil || n == 1 {
			return false, err
		}
		// Lost the swap: another poll stamped the row after our read, so
		// this one arrived inside the interval of that poll.
	}

	if _, err := s.db.ExecContext(ctx,
		`UPDATE device_codes
		 SET last_polled_at = ?, interval_seconds = interval_seconds + 5
		 WHERE device_code_hash = ?`,
		now, hash,
	); err != nil {
		return false, s.fail("poll_device_code", fmt.Errorf("sqlite: poll device code slow_down: %w", err))
	}
	return true, nil
}

// ApproveDeviceCode atomically stamps the row as approved by `id` only
// when it is still pending (both approved_at and denied_at NULL) and not
// expired at now. Otherwise it returns ErrDeviceCodeNotPending: a second
// click on Approve, an Approve after Deny, an expired code, or a completely
// unknown user_code all collapse to the same outward error so the UI cannot
// be coaxed into revealing whether a user_code is in use.
func (s *Store) ApproveDeviceCode(ctx context.Context, userCode string, id oidc.Identity, now time.Time) error {
	return s.decideDeviceCode(ctx, now,
		`UPDATE device_codes
		 SET approved_at = ?, connector_id = ?, subject = ?, email = ?
		 WHERE user_code = ?
		   AND approved_at IS NULL
		   AND denied_at IS NULL`,
		[]any{now, id.ConnectorID, id.Subject, id.Email, userCode},
		userCode,
	)
}

// DenyDeviceCode is ApproveDeviceCode's counterpart; the same pending and
// unexpired conditions apply.
func (s *Store) DenyDeviceCode(ctx context.Context, userCode string, now time.Time) error {
	return s.decideDeviceCode(ctx, now,
		`UPDATE device_codes
		 SET denied_at = ?
		 WHERE user_code = ?
		   AND approved_at IS NULL
		   AND denied_at IS NULL`,
		[]any{now, userCode},
		userCode,
	)
}

// decideDeviceCode checks expiry before the conditional UPDATE. The check is
// done in Go (stored timestamps are Go time strings SQLite cannot compare
// reliably) and is race-free because expires_at never changes after insert.
// /token rejects an expired code anyway; refusing the decision too keeps the
// row from ever reading as approved past its lifetime.
func (s *Store) decideDeviceCode(ctx context.Context, now time.Time, stmt string, args []any, userCode string) error {
	var expiresAt time.Time
	err := s.db.QueryRowContext(ctx,
		`SELECT expires_at FROM device_codes WHERE user_code = ?`, userCode,
	).Scan(&expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrDeviceCodeNotPending
	}
	if err != nil {
		return s.fail("decide_device_code", fmt.Errorf("sqlite: decide device code: %w", err))
	}
	if !now.Before(expiresAt) {
		return fmt.Errorf("%w: expired", ErrDeviceCodeNotPending)
	}

	res, err := s.db.ExecContext(ctx, stmt, args...)
	if err != nil {
		return s.fail("decide_device_code", fmt.Errorf("sqlite: decide device code: %w", err))
	}
	n, err := res.RowsAffected()
	if err != nil {
		return s.fail("decide_device_code", fmt.Errorf("sqlite: decide device code rows: %w", err))
	}
	if n == 0 {
		return ErrDeviceCodeNotPending
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
		dc           = oidc.DeviceCode{Code: deviceCode}
		connectorID  sql.NullString
		subject      sql.NullString
		email        sql.NullString
		approvedAt   sql.NullTime
		deniedAt     sql.NullTime
		lastPolledAt sql.NullTime
	)
	err := s.db.QueryRowContext(ctx,
		`DELETE FROM device_codes WHERE device_code_hash = ?
		 RETURNING user_code, client_id, scope, connector_id, subject, email,
		           approved_at, denied_at, last_polled_at, interval_seconds,
		           created_at, expires_at`,
		secret.Hash(deviceCode),
	).Scan(
		&dc.UserCode, &dc.ClientID, &dc.Scope, &connectorID, &subject, &email,
		&approvedAt, &deniedAt, &lastPolledAt, &dc.IntervalSeconds,
		&dc.CreatedAt, &dc.ExpiresAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return oidc.DeviceCode{}, ErrDeviceCodeNotFound
	}
	if err != nil {
		return oidc.DeviceCode{}, s.fail("consume_device_code", fmt.Errorf("sqlite: consume device code: %w", err))
	}
	dc.ConnectorID = connectorID.String
	dc.Subject = subject.String
	dc.Email = email.String
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
