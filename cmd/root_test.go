package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/onhotpath/tempogate/buildinfo"
)

func TestVersionFlagMatchesVersionCommand(t *testing.T) {
	for _, args := range [][]string{{"--version"}, {"version"}} {
		root := NewRootCmd(newVersionCmd())
		var output bytes.Buffer
		root.SetOut(&output)
		root.SetArgs(args)
		if err := root.Execute(); err != nil {
			t.Fatalf("tempogate %v: %v", args, err)
		}
		if want := buildinfo.Version() + "\n"; output.String() != want {
			t.Errorf("tempogate %v output = %q, want %q", args, output.String(), want)
		}
	}
}

// --config is consumed by the config loader before cobra runs (see
// config.PathFromArgs); the root still declares it so every subcommand
// accepts it and --help documents it.
func TestConfigFlagAcceptedByEverySubcommand(t *testing.T) {
	for _, args := range [][]string{
		{"--config", "/etc/tempogate.yaml", "version"},
		{"version", "--config", "/etc/tempogate.yaml"},
		{"version", "--config=/etc/tempogate.yaml"},
	} {
		root := NewRootCmd(newVersionCmd())
		root.SetOut(new(bytes.Buffer))
		root.SetArgs(args)
		if err := root.Execute(); err != nil {
			t.Fatalf("tempogate %v: %v", args, err)
		}
	}
	root := NewRootCmd(newVersionCmd())
	f := root.PersistentFlags().Lookup("config")
	if f == nil {
		t.Fatal("root command must declare a persistent --config flag")
	}
	if !strings.Contains(f.Usage, "TEMPOGATE_CONFIG") {
		t.Errorf("--config usage should mention TEMPOGATE_CONFIG, got %q", f.Usage)
	}
}
