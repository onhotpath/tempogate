package cmd

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/onhotpath/tempogate/buildinfo"
)

type versionPayload struct {
	Version   string `json:"version"`
	Tag       string `json:"tag"`
	Commit    string `json:"commit"`
	BuildDate string `json:"buildDate"`
}

func newVersionCmd() *cobra.Command {
	var detailed, asJSON bool
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print build version information",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return printVersion(cmd.OutOrStdout(), detailed, asJSON)
		},
	}
	cmd.Flags().BoolVarP(&detailed, "detailed", "d", false, "Print version, tag, commit, and build date")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Emit output as JSON (implies --detailed)")
	return cmd
}

func printVersion(w io.Writer, detailed, asJSON bool) error {
	if asJSON {
		payload := versionPayload{
			Version:   buildinfo.Version(),
			Tag:       buildinfo.Tag(),
			Commit:    buildinfo.Commit(),
			BuildDate: buildinfo.DateTime(),
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(payload)
	}
	if detailed {
		_, err := fmt.Fprintf(w,
			"version:    %s\ntag:        %s\ncommit:     %s\nbuildDate:  %s\n",
			buildinfo.Version(), buildinfo.Tag(), buildinfo.Commit(), buildinfo.DateTime(),
		)
		return err
	}
	_, err := fmt.Fprintln(w, buildinfo.Version())
	return err
}
