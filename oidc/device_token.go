package oidc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

// deviceCodeGrant implements RFC 8628 §3.4 (device-code redemption) plus the
// full §3.5 error matrix the CLI's polling loop drives off of. Token issuance
// itself reuses (*Token).issue so claim shape and TTL are byte-identical to
// the authorization_code path — the device-code holder gets the same Token a
// loopback-login user would, minus the nonce concept which device flow does
// not have.
//
// The dispatch order is deliberate:
//
//  1. Required-field check (invalid_request) — cheap, no I/O.
//  2. Lookup (invalid_grant on miss).
//  3. client_id binding check (invalid_client on mismatch) — done before any
//     state mutation so a stranger probing other clients' device_codes
//     cannot influence the row.
//  4. slow_down — strictly from stored interval; bumps it and short-circuits.
//     A too-fast poll never advances the state machine, so an expired or
//     denied row that is also being polled too fast still returns slow_down
//     first (the client slows down and gets the truthful status next time).
//  5. last_polled_at stamp on the well-paced poll, atomic with step 4.
//  6. Expiry / denial — consumed on the first observing poll, so a second
//     poll returns invalid_grant rather than the same status indefinitely.
//  7. Approval gate — authorization_pending until the user clicks Approve.
//  8. Atomic consume + mint via the shared (*Token).issue.
func (t *Token) deviceCodeGrant(ctx context.Context, form url.Values, authHeader string) (*tokenOutput, error) {
	if t.devices == nil {
		// No DeviceCodeStore wired in: the device flow is not enabled on this
		// deployment. Surface it as unsupported_grant_type so the CLI's error
		// path matches what the dispatcher would have done if the grant were
		// not in the switch at all.
		return nil, oauthErr(http.StatusBadRequest, "unsupported_grant_type", "device_code grant is not enabled on this server")
	}

	deviceCode := form.Get("device_code")
	if deviceCode == "" {
		return nil, oauthErr(http.StatusBadRequest, "invalid_request", "device_code is required")
	}
	clientID, secret := clientCredentials(form, authHeader)
	if clientID == "" {
		return nil, oauthErr(http.StatusBadRequest, "invalid_request", "client_id is required")
	}
	if _, err := t.authenticateClient(clientID, secret, GrantTypeDeviceCode); err != nil {
		return nil, err
	}

	dc, err := t.devices.LookupDeviceCodeByDeviceCode(ctx, deviceCode)
	if errors.Is(err, ErrDeviceCodeNotFound) {
		return nil, oauthErr(http.StatusBadRequest, "invalid_grant", "unknown or already-consumed device_code")
	}
	if err != nil {
		return nil, fmt.Errorf("oidc: lookup device code: %w", err)
	}

	if clientID != dc.ClientID {
		return nil, oauthErr(http.StatusUnauthorized, "invalid_client", "client_id does not match the device authorization request")
	}

	now := t.now()

	// §3.5 slow_down — strictly from the stored interval, which includes any
	// prior bumps. A poll that arrives inside the window bumps the floor by
	// +5s; a well-paced poll never bumps. The store decides and records in
	// one atomic step, so parallel polls cannot all pass as well-paced.
	slowDown, err := t.devices.PollDeviceCode(ctx, deviceCode, now)
	if errors.Is(err, ErrDeviceCodeNotFound) {
		return nil, oauthErr(http.StatusBadRequest, "invalid_grant", "unknown or already-consumed device_code")
	}
	if err != nil {
		return nil, fmt.Errorf("oidc: record device code poll: %w", err)
	}
	if slowDown {
		return nil, oauthErr(http.StatusBadRequest, "slow_down", "polling faster than the agreed interval")
	}

	// Expiry and denial are terminal — consume the row on the first observing
	// poll so a second poll cannot keep ringing the same bell. The consume
	// failure is swallowed: another concurrent poll may have already deleted
	// the row, and the outcome to the caller is unchanged either way.
	if now.After(dc.ExpiresAt) {
		_, _ = t.devices.ConsumeDeviceCode(ctx, deviceCode)
		return nil, oauthErr(http.StatusBadRequest, "expired_token", "device_code expired")
	}
	if dc.DeniedAt != nil {
		// Denied by the person on the verification page, or by tempogate
		// because no authorization rule grants them anything; the row does
		// not say which, so neither does the description.
		_, _ = t.devices.ConsumeDeviceCode(ctx, deviceCode)
		return nil, oauthErr(http.StatusBadRequest, "access_denied", "the device authorization request was denied")
	}
	if dc.ApprovedAt == nil {
		return nil, oauthErr(http.StatusBadRequest, "authorization_pending", "user has not yet completed the device authorization")
	}

	// Approved — single-use claim. The race between two concurrent post-
	// approval polls is resolved by the store: the loser sees
	// ErrDeviceCodeNotFound and gets invalid_grant.
	final, err := t.devices.ConsumeDeviceCode(ctx, deviceCode)
	if errors.Is(err, ErrDeviceCodeNotFound) {
		return nil, oauthErr(http.StatusBadRequest, "invalid_grant", "device_code already consumed")
	}
	if err != nil {
		return nil, fmt.Errorf("oidc: consume device code: %w", err)
	}

	if final.Subject == "" {
		return nil, errLegacyGrant("device code")
	}

	// RFC 8628 has no nonce concept; minting with empty nonce is the correct
	// behaviour and matches authorization_code on every other claim.
	id := Identity{Subject: final.Subject, Email: final.Email}
	out, err := t.issue(ctx, id, final.ClientID, "", lineage{})
	if errors.Is(err, errNoPermissions) {
		// The verification page refuses such a person before approving, so
		// this is a rule removed after the approval. RFC 8628 §3.5
		// access_denied ends the CLI's polling.
		return nil, t.refuseNoPermissions(ctx, grantLabelDeviceCode, id, final.ClientID, "access_denied")
	}
	return out, err
}
