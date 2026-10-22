package google

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestFxWarnsWithoutHostedDomains pins the startup warning for the
// email-suffix-only gate: it fires when OIDC_ALLOWED_HOSTED_DOMAINS is unset
// (or only separators) and stays quiet in Workspace mode.
func TestFxWarnsWithoutHostedDomains(t *testing.T) {
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
			conn, err := newFx(params{
				Logger:        slog.New(slog.NewTextHandler(&buf, nil)),
				AuthEndpoint:  "https://accounts.google.com/o/oauth2/v2/auth",
				HostedDomains: tc.hosted,
			})
			require.NoError(t, err)
			require.NotNil(t, conn)
			if tc.warn {
				require.Contains(t, buf.String(), "level=WARN")
				require.Contains(t, buf.String(), "OIDC_ALLOWED_HOSTED_DOMAINS is not set")
				return
			}
			require.Empty(t, buf.String())
		})
	}
}
