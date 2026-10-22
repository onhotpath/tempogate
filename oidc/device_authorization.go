package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/onhotpath/tempogate/internal/clock"
)

const (
	// DeviceAuthorizationPath is exported so the OIDC discovery document can
	// advertise the same device_authorization_endpoint this handler
	// registers, keeping the two from drifting.
	DeviceAuthorizationPath = "/device_authorization"

	// DevicePath is the verification-page path the response's
	// verification_uri / verification_uri_complete point to. The page itself
	// is the next epic stage (the templated approval UI); the URL contract
	// is fixed here so the CLI and the discovery document can be wired
	// independently of when the UI lands.
	DevicePath = "/device"

	// deviceCodeTTL is the RFC 8628 §3.2 `expires_in` we advertise: 15 min
	// balances CLI usability (a human switches devices, opens the URL,
	// completes Google SSO, clicks Approve) against the row's liveness in
	// device_codes.
	deviceCodeTTL = 15 * time.Minute

	// defaultPollInterval is the RFC 8628 §3.2 default poll interval (5 s).
	// We advertise this verbatim and seed every device_codes row with it so
	// the server-enforced slow_down rule (§3.5) has a defined baseline to
	// bump from.
	defaultPollInterval = 5

	// userCodeAlphabet is RFC 8628 §6.1 base20 (no vowels) plus four digits
	// chosen so they do not collide visually with the kept letters (drops
	// 0/1/2/5/6/8). 24 characters total; numeric ratio = 16.7% (well under
	// the §6.1 50% ceiling).
	userCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ3479"

	// userCodeLen is the 8-character canonical length: 24^8 ≈ 1.1e11 codes,
	// so a duplicate over the 15-minute window is astronomically unlikely.
	userCodeLen = 8

	// deviceCodeEntropyBytes carries 256 bits of entropy in the long
	// machine-side token, base64url-encoded to 43 ASCII characters with no
	// padding — comfortably inside the §3.2 1-octet character set.
	deviceCodeEntropyBytes = 32

	// userCodeMaxRetries caps the regeneration loop on duplicate-save
	// collisions. 3 attempts in a 24^8 space with a 15-minute TTL is far
	// past the point at which a regression in the rejection sampler or a
	// genuine astronomical collision can be distinguished — the loop is a
	// defense against logic regressions, not a probability play.
	userCodeMaxRetries = 3

	// userCodeRandRejectionCap is the largest multiple of 24 strictly less
	// than 256 (24*10 = 240). Bytes ≥ this cap are rejected to keep the
	// `byte % 24` projection unbiased. Without the cap, the first 16
	// alphabet characters would be drawn ~17% more often than the last 8.
	userCodeRandRejectionCap = 240
)

// DeviceAuthorization serves POST /device_authorization (RFC 8628 §3.1, §3.2):
// a headless client (CLI, no local browser) initiates a device flow, gets back
// a long machine-side device_code + a short human-typeable user_code + the
// verification URL its user opens on a second device, and starts polling
// /token with the device_code.
type DeviceAuthorization struct {
	store         DeviceCodeStore
	clients       ClientRegistry
	issuer        string
	now           func() time.Time
	newDeviceCode func() (string, error)
	newUserCode   func() (string, error)
}

type DeviceAuthorizationOption func(*DeviceAuthorization)

// WithDeviceAuthorizationClock swaps the clock used to stamp device_codes
// rows. For tests.
func WithDeviceAuthorizationClock(now func() time.Time) DeviceAuthorizationOption {
	return func(h *DeviceAuthorization) { h.now = now }
}

// WithDeviceCodeGenerator swaps the 32-byte-entropy device_code generator.
// For tests.
func WithDeviceCodeGenerator(fn func() (string, error)) DeviceAuthorizationOption {
	return func(h *DeviceAuthorization) { h.newDeviceCode = fn }
}

// WithUserCodeGenerator swaps the human-typeable user_code generator. The
// generator returns the canonical (no-dash) form; the handler is responsible
// for formatting the dashed display form in the wire response. For tests.
func WithUserCodeGenerator(fn func() (string, error)) DeviceAuthorizationOption {
	return func(h *DeviceAuthorization) { h.newUserCode = fn }
}

func NewDeviceAuthorization(
	store DeviceCodeStore,
	clients ClientRegistry,
	issuer string,
	opts ...DeviceAuthorizationOption,
) *DeviceAuthorization {
	h := &DeviceAuthorization{
		store:         store,
		clients:       clients,
		issuer:        strings.TrimRight(issuer, "/"),
		now:           clock.Now,
		newDeviceCode: randomDeviceCode,
		newUserCode:   randomUserCode,
	}
	for _, o := range opts {
		o(h)
	}
	return h
}

// deviceAuthorizationInput takes the raw form body verbatim, matching the
// /token handler's approach. RFC 8628 §3.1 mandates
// application/x-www-form-urlencoded, and parsing it by hand keeps the
// client_id / scope dispatch explicit.
type deviceAuthorizationInput struct {
	RawBody []byte `contentType:"application/x-www-form-urlencoded"`
}

// deviceAuthorizationOutput is the RFC 8628 §3.2 response shape. Cache-Control
// no-store is mandated so intermediaries never retain the device_code or
// user_code.
type deviceAuthorizationOutput struct {
	CacheControl string `header:"Cache-Control"`
	Body         deviceAuthorizationBody
}

type deviceAuthorizationBody struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

func (h *DeviceAuthorization) Register(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "device-authorization",
		Method:      http.MethodPost,
		Path:        DeviceAuthorizationPath,
		Summary:     "OAuth2 device authorization endpoint (RFC 8628 §3.1)",
		Tags:        []string{"oidc"},
	}, func(ctx context.Context, in *deviceAuthorizationInput) (*deviceAuthorizationOutput, error) {
		return h.handle(ctx, in)
	})
}

func (h *DeviceAuthorization) handle(ctx context.Context, in *deviceAuthorizationInput) (*deviceAuthorizationOutput, error) {
	form, err := url.ParseQuery(string(in.RawBody))
	if err != nil {
		return nil, oauthErr(http.StatusBadRequest, "invalid_request", "malformed form body")
	}

	if err := checkParamLengths(
		paramCap{"client_id", form.Get("client_id"), maxClientIDLen},
		paramCap{"scope", form.Get("scope"), maxScopeLen},
	); err != nil {
		return nil, err
	}

	clientID := form.Get("client_id")
	if clientID == "" {
		return nil, oauthErr(http.StatusBadRequest, "invalid_request", "client_id is required")
	}
	client, ok := h.clients[clientID]
	if !ok || client.Secret != "" {
		// RFC 8628 §3.1: the device flow is for public clients. Unknown and
		// confidential collapse to the same outward error so a caller
		// cannot probe which client_ids are configured confidential.
		return nil, oauthErr(http.StatusUnauthorized, "invalid_client", "client_id is not a registered public client")
	}
	if !client.Allows(GrantTypeDeviceCode) {
		// A redirect-URI client is registered for the authorization-code
		// flow only; the device grant needs the device-only registration.
		return nil, oauthErr(http.StatusBadRequest, "unauthorized_client", "client_id is not registered for the device authorization grant")
	}

	dc, err := h.mint(ctx, clientID, form.Get("scope"))
	if err != nil {
		return nil, err
	}

	return &deviceAuthorizationOutput{
		CacheControl: "no-store",
		Body: deviceAuthorizationBody{
			DeviceCode:              dc.Code,
			UserCode:                formatUserCode(dc.UserCode),
			VerificationURI:         h.issuer + DevicePath,
			VerificationURIComplete: h.issuer + DevicePath + "?user_code=" + url.QueryEscape(formatUserCode(dc.UserCode)),
			ExpiresIn:               int(deviceCodeTTL.Seconds()),
			Interval:                defaultPollInterval,
		},
	}, nil
}

// mint runs the generate→save loop. user_code collisions in a 24^8 space
// across a 15-minute window are astronomically unlikely, but a regression in
// the rejection sampler (or a clock-frozen test seed) could quietly produce
// duplicates — the bounded retry keeps that failure surfaced rather than
// hanging the handler.
func (h *DeviceAuthorization) mint(ctx context.Context, clientID, scope string) (DeviceCode, error) {
	now := h.now()
	for attempt := 0; attempt < userCodeMaxRetries; attempt++ {
		deviceCode, err := h.newDeviceCode()
		if err != nil {
			return DeviceCode{}, fmt.Errorf("oidc: generate device code: %w", err)
		}
		userCode, err := h.newUserCode()
		if err != nil {
			return DeviceCode{}, fmt.Errorf("oidc: generate user code: %w", err)
		}

		dc := DeviceCode{
			Code:            deviceCode,
			UserCode:        userCode,
			ClientID:        clientID,
			Scope:           scope,
			IntervalSeconds: defaultPollInterval,
			CreatedAt:       now,
			ExpiresAt:       now.Add(deviceCodeTTL),
		}
		err = h.store.SaveDeviceCode(ctx, dc)
		if err == nil {
			return dc, nil
		}
		if !errors.Is(err, ErrDuplicateDeviceCode) {
			return DeviceCode{}, fmt.Errorf("oidc: persist device code: %w", err)
		}
		// Duplicate — fall through and regenerate both halves on the next
		// iteration. Regenerating device_code is free; doing it spares the
		// caller a special-case branch for the (effectively impossible) PK
		// collision.
	}
	return DeviceCode{}, fmt.Errorf("oidc: exhausted device-code regeneration retries (%d)", userCodeMaxRetries)
}

// formatUserCode inserts a single dash at the midpoint of an 8-character
// canonical user_code, producing the "BCDF-GHJK" wire form RFC 8628 §6.1
// recommends for human typeability. The canonical form remains the
// authoritative storage shape; this is purely presentational.
func formatUserCode(canonical string) string {
	if len(canonical) <= userCodeLen/2 {
		return canonical
	}
	return canonical[:userCodeLen/2] + "-" + canonical[userCodeLen/2:]
}

// randomDeviceCode draws 32 bytes from crypto/rand and base64url-encodes
// them. Output is 43 ASCII characters; no padding (RawURLEncoding).
func randomDeviceCode() (string, error) {
	b := make([]byte, deviceCodeEntropyBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// randomUserCode draws userCodeLen characters from userCodeAlphabet using
// rejection sampling against a single byte's range: bytes ≥
// userCodeRandRejectionCap (= 24*10) are discarded so that `byte % 24` is
// unbiased. The read is buffered to amortise crypto/rand calls and the
// rejection rate (16/256 ≈ 6.25%) is low enough that one buffered read
// suffices in the overwhelming majority of cases; we top up only if the
// rejection rate happened to spike on this draw.
func randomUserCode() (string, error) {
	out := make([]byte, 0, userCodeLen)
	// 16 random bytes ≫ the 8 we need even at the worst-case rejection
	// rate, so the inner read loop almost always exits on the first pass.
	buf := make([]byte, 16)
	for len(out) < userCodeLen {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		for _, b := range buf {
			if len(out) >= userCodeLen {
				break
			}
			if b >= userCodeRandRejectionCap {
				continue
			}
			out = append(out, userCodeAlphabet[int(b)%len(userCodeAlphabet)])
		}
	}
	return string(out), nil
}
