package servercmd

import (
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/fx"

	"github.com/onhotpath/tempogate/keys"
	"github.com/onhotpath/tempogate/state/sqlite"
)

type keysParams struct {
	fx.In

	Store *sqlite.Store
	Keys  *keys.Keys
}

func newKeysCmd(p keysParams) *cobra.Command {
	root := &cobra.Command{
		Use:   "keys",
		Short: "Manage tempogate signing keys",
	}
	root.AddCommand(newKeysGenerateCmd(p), newKeysEncryptCmd(p))
	return root
}

func newKeysGenerateCmd(p keysParams) *cobra.Command {
	var force bool
	c := &cobra.Command{
		Use:   "generate",
		Short: "Generate the JWT signing keypair (fails if one exists; use --force to rotate)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			if err := storeReady(ctx, p.Store); err != nil {
				return err
			}

			kp, err := p.Keys.Generate(ctx, force)
			if err != nil {
				return err
			}

			cmd.Printf("generated keypair: kid=%s alg=%s created_at=%s\n",
				kp.Kid, kp.Alg, kp.CreatedAt.UTC().Format(time.RFC3339))
			return nil
		},
	}
	c.Flags().BoolVar(&force, "force", false, "rotate by adding a new keypair even if one already exists")
	return c
}

// newKeysEncryptCmd encrypts the signing keys an earlier run stored in clear,
// once KEYS_ENCRYPTION_KEY is configured. New keys are encrypted on write;
// this is the one-off step for the existing ones. A running server keeps its
// keys in memory, so this is safe while it serves; its next start needs the
// KEK.
func newKeysEncryptCmd(p keysParams) *cobra.Command {
	return &cobra.Command{
		Use:   "encrypt",
		Short: "Encrypt stored signing keys with KEYS_ENCRYPTION_KEY (idempotent)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			if err := storeReady(ctx, p.Store); err != nil {
				return err
			}
			n, err := p.Keys.EncryptStored(ctx, p.Store)
			if err != nil {
				return err
			}
			cmd.Printf("encrypted %d keypair(s)\n", n)
			return nil
		},
	}
}
