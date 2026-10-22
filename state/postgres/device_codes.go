package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/onhotpath/tempogate/oidc"
	"github.com/onhotpath/tempogate/state/internal/secret"
)

// ErrDuplicateDeviceCode is returned by SaveDeviceCode when a row with the
// same device_code or user_code already exists. Rooted at
// oidc.ErrDuplicateDeviceCode, so the /device_authorization handler
// regenerates on errors.Is without importing this package.
var ErrDuplicateDeviceCode = fmt.Errorf("%w: postgres duplicate", oidc.ErrDuplicateDeviceCode)

// ErrDeviceCodeNotFound is returned by a lookup or consume that finds no row,
// because the row was never written, was already consumed, or was deleted
// by the reaper. Rooted at oidc.ErrDeviceCodeNotFound.
var ErrDeviceCodeNotFound = fmt.Errorf("%w: postgres", oidc.ErrDeviceCodeNotFound)

// ErrDeviceCodeNotPending is returned by Approve / Deny when the code is no
// longer pending (already decided, expired or unknown: the UI must not tell
// them apart). Rooted at oidc.ErrDeviceCodeNotPending.
var ErrDeviceCodeNotPending = fmt.Errorf("%w: postgres", oidc.ErrDeviceCodeNotPending)

const deviceCodeColumns = `user_code, client_id, scope, connector_id, subject, email,
	approved_at, denied_at, last_polled_at, interval_seconds,
	created_at, expires_at`

func (s *Store) SaveDeviceCode(ctx context.Context, dc oidc.DeviceCode) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO device_codes
		   (device_code_hash, user_code, client_id, scope, connector_id, subject, email,
		    approved_at, denied_at, last_polled_at, interval_seconds,
		    created_at, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		secret.Hash(dc.Code), dc.UserCode, dc.ClientID, dc.Scope, nullString(dc.ConnectorID), nullString(dc.Subject), nullString(dc.Email),
		dc.ApprovedAt, dc.DeniedAt, dc.LastPolledAt,
		dc.IntervalSeconds, dc.CreatedAt, dc.ExpiresAt,
	)
	if isUniqueViolation(err) {
		return ErrDuplicateDeviceCode
	}
	if err != nil {
		return s.fail("save_device_code", fmt.Errorf("postgres: save device code: %w", err))
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

// LookupDeviceCodeByUserCode resolves the verification-page path's row. The
// caller normalises the user_code (uppercase, no dashes) first. The result's
// Code is empty: only the device code's hash is stored.
func (s *Store) LookupDeviceCodeByUserCode(ctx context.Context, userCode string) (oidc.DeviceCode, error) {
	return s.lookupDeviceCode(ctx, "user_code", userCode)
}

func (s *Store) lookupDeviceCode(ctx context.Context, column, value string) (oidc.DeviceCode, error) {
	// #nosec G202 -- column is one of the two constants above, never input.
	dc, err := scanDeviceCode(s.pool.QueryRow(ctx,
		`SELECT `+deviceCodeColumns+` FROM device_codes WHERE `+column+` = $1`, value))
	if errors.Is(err, pgx.ErrNoRows) {
		return oidc.DeviceCode{}, ErrDeviceCodeNotFound
	}
	if err != nil {
		return oidc.DeviceCode{}, s.fail("lookup_device_code", fmt.Errorf("postgres: lookup device code by %s: %w", column, err))
	}
	return dc, nil
}

// PollDeviceCode records a /token poll and enforces the RFC 8628 §3.5
// minimum interval. It locks the row FOR UPDATE, so concurrent polls of one
// code run one after another: the first well-paced one stamps
// last_polled_at, and every poll that then finds itself inside the interval
// is slow_down, which bumps interval_seconds by 5 and reports true.
func (s *Store) PollDeviceCode(ctx context.Context, deviceCode string, now time.Time) (bool, error) {
	var slowDown bool
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var (
			hash       = secret.Hash(deviceCode)
			lastPolled *time.Time
			interval   int
		)
		if err := tx.QueryRow(ctx,
			`SELECT last_polled_at, interval_seconds FROM device_codes
			 WHERE device_code_hash = $1 FOR UPDATE`,
			hash,
		).Scan(&lastPolled, &interval); err != nil {
			return err
		}
		slowDown = lastPolled != nil && now.Sub(*lastPolled) < time.Duration(interval)*time.Second
		bump := 0
		if slowDown {
			bump = 5
		}
		_, err := tx.Exec(ctx,
			`UPDATE device_codes
			 SET last_polled_at = $1, interval_seconds = interval_seconds + $2
			 WHERE device_code_hash = $3`,
			now, bump, hash,
		)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrDeviceCodeNotFound
	}
	if err != nil {
		return false, s.fail("poll_device_code", fmt.Errorf("postgres: poll device code: %w", err))
	}
	return slowDown, nil
}

// ApproveDeviceCode stamps the row as approved by id only while it is still
// pending (approved_at and denied_at both NULL) and unexpired at now, in one
// conditional UPDATE. Anything else, an unknown user_code included, is
// ErrDeviceCodeNotPending, so the UI cannot be coaxed into revealing whether
// a user_code is in use.
func (s *Store) ApproveDeviceCode(ctx context.Context, userCode string, id oidc.Identity, now time.Time) error {
	return s.decideDeviceCode(ctx,
		`UPDATE device_codes
		 SET approved_at = $1, connector_id = $3, subject = $4, email = $5
		 WHERE user_code = $2 AND approved_at IS NULL AND denied_at IS NULL AND expires_at > $1`,
		now, userCode, id.ConnectorID, id.Subject, id.Email,
	)
}

// DenyDeviceCode is ApproveDeviceCode's counterpart; the same pending and
// unexpired conditions apply.
func (s *Store) DenyDeviceCode(ctx context.Context, userCode string, now time.Time) error {
	return s.decideDeviceCode(ctx,
		`UPDATE device_codes
		 SET denied_at = $1
		 WHERE user_code = $2 AND approved_at IS NULL AND denied_at IS NULL AND expires_at > $1`,
		now, userCode,
	)
}

func (s *Store) decideDeviceCode(ctx context.Context, stmt string, args ...any) error {
	tag, err := s.pool.Exec(ctx, stmt, args...)
	if err != nil {
		return s.fail("decide_device_code", fmt.Errorf("postgres: decide device code: %w", err))
	}
	if tag.RowsAffected() == 0 {
		return ErrDeviceCodeNotPending
	}
	return nil
}

// ConsumeDeviceCode atomically deletes and returns the row; of concurrent
// /token polls exactly one gets it and the others ErrDeviceCodeNotFound.
// Called only on the final token-mint path, after an Approve has stamped the
// row.
func (s *Store) ConsumeDeviceCode(ctx context.Context, deviceCode string) (oidc.DeviceCode, error) {
	dc, err := scanDeviceCode(s.pool.QueryRow(ctx,
		`DELETE FROM device_codes WHERE device_code_hash = $1 RETURNING `+deviceCodeColumns,
		secret.Hash(deviceCode)))
	if errors.Is(err, pgx.ErrNoRows) {
		return oidc.DeviceCode{}, ErrDeviceCodeNotFound
	}
	if err != nil {
		return oidc.DeviceCode{}, s.fail("consume_device_code", fmt.Errorf("postgres: consume device code: %w", err))
	}
	dc.Code = deviceCode
	return dc, nil
}

func scanDeviceCode(r pgx.Row) (oidc.DeviceCode, error) {
	var (
		dc                          oidc.DeviceCode
		connectorID, subject, email *string
	)
	if err := r.Scan(
		&dc.UserCode, &dc.ClientID, &dc.Scope, &connectorID, &subject, &email,
		&dc.ApprovedAt, &dc.DeniedAt, &dc.LastPolledAt, &dc.IntervalSeconds,
		&dc.CreatedAt, &dc.ExpiresAt,
	); err != nil {
		return oidc.DeviceCode{}, err
	}
	if connectorID != nil {
		dc.ConnectorID = *connectorID
	}
	if subject != nil {
		dc.Subject = *subject
	}
	if email != nil {
		dc.Email = *email
	}
	return dc, nil
}

// nullString stores "" as NULL, as SQLite does for the identity columns of
// a device code not yet approved.
func nullString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
