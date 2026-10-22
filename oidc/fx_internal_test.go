package oidc

import (
	"encoding/base64"
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
