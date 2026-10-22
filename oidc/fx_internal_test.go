package oidc

import (
	"context"
	"encoding/base64"
	"errors"
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

type failingSourcesConnector struct{ Connector }

func (failingSourcesConnector) ID() string { return "okta" }

func (failingSourcesConnector) FormActionSources(context.Context) ([]string, error) {
	return nil, errors.New("discovery failed")
}

// TestDeviceUIRegistrarFailsOnConnectorSources: the device page's CSP is
// built at startup, so a connector that cannot name its origins stops the
// server rather than shipping a page whose redirect chain the browser drops.
func TestDeviceUIRegistrarFailsOnConnectorSources(t *testing.T) {
	_, err := newDeviceUIRegistrar(deviceUIParams{Connectors: &Connectors{active: failingSourcesConnector{}}})
	require.ErrorContains(t, err, `connector "okta" form-action sources`)
}
