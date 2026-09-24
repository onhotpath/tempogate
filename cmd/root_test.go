package cmd

import (
	"bytes"
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
