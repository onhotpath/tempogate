package servercmd

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/onhotpath/tempogate/config"
)

func TestCheckIssuer(t *testing.T) {
	for _, tc := range []struct {
		name          string
		issuer        string
		allowInsecure bool
		wantErr       bool
		wantWarn      bool
	}{
		{name: "https", issuer: "https://tempogate.example.com"},
		{name: "loopback http", issuer: "http://127.0.0.1:8000"},
		{name: "plain http", issuer: "http://tempogate:8000", wantErr: true},
		{name: "plain http allowed", issuer: "http://tempogate:8000", allowInsecure: true, wantWarn: true},
		// The opt-in only relaxes the check; a secure issuer logs nothing.
		{name: "https with opt-in", issuer: "https://tempogate.example.com", allowInsecure: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			core, logs := observer.New(zap.WarnLevel)
			cfg := &config.Config{OIDC: config.OIDCConfig{Issuer: tc.issuer, AllowInsecureIssuer: tc.allowInsecure}}

			err := checkIssuer(cfg, zap.New(core))
			if tc.wantErr {
				require.ErrorContains(t, err, "must use https")
			} else {
				require.NoError(t, err)
			}
			if tc.wantWarn {
				require.Equal(t, 1, logs.FilterMessageSnippet("insecure OIDC issuer allowed").Len())
			} else {
				require.Zero(t, logs.Len())
			}
		})
	}
}
