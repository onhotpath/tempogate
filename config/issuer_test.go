package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateIssuer(t *testing.T) {
	for _, tc := range []struct {
		issuer string
		ok     bool
	}{
		{issuer: "https://tempogate.example.com", ok: true},
		{issuer: "https://tempogate.example.com/idp", ok: true},
		{issuer: "HTTPS://tempogate.example.com", ok: true},
		{issuer: "https://10.0.0.5:8443", ok: true},

		// Loopback is exempt: the issuer is only reachable from the host.
		{issuer: "http://127.0.0.1:8000", ok: true},
		{issuer: "http://127.0.0.2:8000", ok: true},
		{issuer: "http://localhost:8000", ok: true},
		{issuer: "http://LocalHost:8000/idp", ok: true},
		{issuer: "http://[::1]:8000", ok: true},
		{issuer: "http://localhost", ok: true},

		{issuer: "http://tempogate:8000"},
		{issuer: "http://tempogate.example.com"},
		{issuer: "http://10.0.0.5:8000"},
		{issuer: "http://0.0.0.0:8000"},
		{issuer: "http://[::]:8000"},
		{issuer: "http://localhost.attacker.example"},
		{issuer: "http://127.0.0.1.nip.io"},
		{issuer: "ftp://localhost"},
		{issuer: "tempogate.example.com"},
		{issuer: ""},
		{issuer: "://bad"},
	} {
		t.Run(tc.issuer, func(t *testing.T) {
			err := ValidateIssuer(tc.issuer)
			if tc.ok {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			require.ErrorContains(t, err, "OIDC_ISSUER")
			require.ErrorContains(t, err, "OIDC_ALLOW_INSECURE_ISSUER")
		})
	}
}

func TestDefaultIssuerPassesValidation(t *testing.T) {
	c := defaultConfig()
	require.NoError(t, ValidateIssuer(c.OIDC.Issuer))
	require.False(t, c.OIDC.AllowInsecureIssuer)
}
