package oidc

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDeviceUIRegistrarRejectsInvalidSigningKey(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  string
		want string
	}{
		{"invalid base64url", "!", "must be base64url-encoded"},
		{"wrong length", base64.RawURLEncoding.EncodeToString([]byte("short")), "must decode to 32 bytes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			registrar, err := newDeviceUIRegistrar(deviceUIParams{SigningKeyB64: tc.key})
			require.Nil(t, registrar)
			require.ErrorContains(t, err, tc.want)
		})
	}
}
