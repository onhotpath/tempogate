package oidc

import (
	"bytes"
	"encoding/base64"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSessionSigningKeyIsDecodedOnce pins the wiring: OIDC_SESSION_SIGNING_KEY
// is validated and decoded by one provider, and both consumers take its
// result, so the two cannot disagree on what a valid key is.
func TestSessionSigningKeyIsDecodedOnce(t *testing.T) {
	raw := []byte("0123456789abcdef0123456789abcdef")
	key, err := newSessionSigningKey(sessionSigningKeyParams{SigningKeyB64: base64.RawURLEncoding.EncodeToString(raw)})
	require.NoError(t, err)
	require.Equal(t, sessionSigningKey(raw), key)

	require.NotNil(t, newSessionManager(sessionManagerParams{SigningKey: key}))
	binding, err := newUpstreamBinding(upstreamBindingParams{SigningKey: key, Issuer: "https://tempogate.example.com"})
	require.NoError(t, err)
	require.NotNil(t, binding)
}

func TestSessionSigningKeyRejectsInvalidKeys(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  string
		want string
	}{
		{"missing", "", "OIDC_SESSION_SIGNING_KEY is required"},
		{"invalid base64url", "!", "must be base64url-encoded"},
		{"wrong length", base64.RawURLEncoding.EncodeToString([]byte("short")), "must decode to 32 bytes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, err := newSessionSigningKey(sessionSigningKeyParams{SigningKeyB64: tc.key})
			require.Nil(t, key)
			require.ErrorContains(t, err, tc.want)
		})
	}
}

// TestCallbackRegistrarWarnsWithoutHostedDomains pins the startup warning
// for the email-suffix-only gate: it fires when OIDC_ALLOWED_HOSTED_DOMAINS
// is unset (or only separators) and stays quiet in Workspace mode.
func TestCallbackRegistrarWarnsWithoutHostedDomains(t *testing.T) {
	for _, tc := range []struct {
		name   string
		hosted string
		warn   bool
	}{
		{"unset", "", true},
		{"only separators", " , ", true},
		{"workspace mode", "example.com", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			registrar := newCallbackRegistrar(callbackParams{
				Logger:         slog.New(slog.NewTextHandler(&buf, nil)),
				AllowedDomains: "example.com",
				HostedDomains:  tc.hosted,
			})
			require.NotNil(t, registrar)
			if tc.warn {
				require.Contains(t, buf.String(), "level=WARN")
				require.Contains(t, buf.String(), "OIDC_ALLOWED_HOSTED_DOMAINS is not set")
				return
			}
			require.Empty(t, buf.String())
		})
	}
}
