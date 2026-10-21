package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPathFromArgs(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want Path
	}{
		{name: "absent", args: []string{"serve"}},
		{name: "empty args"},
		{name: "before subcommand", args: []string{"--config", "/etc/tg.yaml", "serve"}, want: "/etc/tg.yaml"},
		{name: "after subcommand", args: []string{"migrate", "--config", "/etc/tg.yaml"}, want: "/etc/tg.yaml"},
		{name: "equals form", args: []string{"keys", "generate", "--config=/etc/tg.yaml"}, want: "/etc/tg.yaml"},
		{name: "last wins", args: []string{"--config", "a.yaml", "serve", "--config=b.yaml"}, want: "b.yaml"},
		{name: "missing value", args: []string{"serve", "--config"}},
		{name: "after terminator", args: []string{"token", "--", "--config", "x.yaml"}},
		{name: "similar flag", args: []string{"--configs", "x.yaml", "--config-file=y"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, PathFromArgs(tc.args))
		})
	}
}

func TestProcessPathPrefersFlagOverEnvironment(t *testing.T) {
	t.Setenv(EnvPath, "/from/env.yaml")
	require.Equal(t, Path("/from/env.yaml"), processPath([]string{"serve"}))
	require.Equal(t, Path("/from/flag.yaml"), processPath([]string{"serve", "--config", "/from/flag.yaml"}))
	t.Setenv(EnvPath, "")
	require.Equal(t, Path(""), processPath([]string{"serve"}))
}

func TestProcessPathReadsOSArgs(t *testing.T) {
	orig := os.Args
	t.Cleanup(func() { os.Args = orig })
	os.Args = []string{"tempogate", "serve", "--config=/etc/tg.yaml"}
	require.Equal(t, Path("/etc/tg.yaml"), ProcessPath())
}
