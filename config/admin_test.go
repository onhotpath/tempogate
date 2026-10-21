package config

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"
)

func TestAdminAllowedHosts(t *testing.T) {
	cases := []struct {
		name   string
		admin  AdminConfig
		expect []string
	}{
		{
			name:   "default derives loopback names from the listener port",
			admin:  AdminConfig{Listener: Listener{IP: net.IPv4(127, 0, 0, 1), Port: 8081}},
			expect: []string{"127.0.0.1:8081", "localhost:8081", "[::1]:8081"},
		},
		{
			// A wildcard bind does not widen the default: the operator must
			// name the hosts remote callers use.
			name:   "wildcard bind keeps the loopback default",
			admin:  AdminConfig{Listener: Listener{IP: net.IPv4zero, Port: 9091}},
			expect: []string{"127.0.0.1:9091", "localhost:9091", "[::1]:9091"},
		},
		{
			name: "explicit list is split and trimmed",
			admin: AdminConfig{
				Listener:     Listener{IP: net.IPv4(127, 0, 0, 1), Port: 8081},
				AllowedHosts: " admin.internal:8081 , ,tempogate-admin ",
			},
			expect: []string{"admin.internal:8081", "tempogate-admin"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expect, adminAllowedHosts(tc.admin))
		})
	}
}

func TestSupplyProjectsAdminAuth(t *testing.T) {
	cfg := defaultConfig()
	cfg.Admin.TokenSHA256 = "abc"
	cfg.Admin.AllowSystemGrants = true

	type projected struct {
		fx.In

		TokenSHA256       string   `name:"admin_token_sha256"`
		AllowedHosts      []string `name:"admin_allowed_hosts"`
		AllowSystemGrants bool     `name:"admin_allow_system_grants"`
	}
	var got projected
	fxtest.New(t,
		Supply(cfg),
		fx.Invoke(func(p projected) { got = p }),
	).RequireStart().RequireStop()

	require.Equal(t, "abc", got.TokenSHA256)
	require.Equal(t, []string{"127.0.0.1:8081", "localhost:8081", "[::1]:8081"}, got.AllowedHosts)
	require.True(t, got.AllowSystemGrants)
}
