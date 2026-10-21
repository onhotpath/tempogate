package servercmd

import (
	"fmt"
	"text/tabwriter"
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

func newKeysCmd(load deps[keysParams]) *cobra.Command {
	root := &cobra.Command{
		Use:   "keys",
		Short: "Manage tempogate signing keys",
	}
	root.AddCommand(newKeysGenerateCmd(load), newKeysEncryptCmd(load), newKeysRetireCmd(load), newKeysListCmd(load))
	return root
}

func newKeysRetireCmd(load deps[keysParams]) *cobra.Command {
	return &cobra.Command{
		Use:   "retire <kid>",
		Short: "Retire a signing keypair: it stops signing now and leaves JWKS after KEYS_RETIREMENT_GRACE",
		Long: "Retire a signing keypair. A running server stops signing with it within KEYS_RELOAD_INTERVAL " +
			"and drops it from /.well-known/jwks.json once KEYS_RETIREMENT_GRACE has passed; from then on " +
			"every token it signed, integration keys included, stops verifying at Temporal. " +
			"The only active keypair cannot be retired: run `tempogate keys generate --force` first.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			return load(ctx, func(p keysParams) error {
				if err := storeReady(ctx, p.Store); err != nil {
					return err
				}
				kp, err := p.Keys.Retire(ctx, args[0])
				if err != nil {
					return err
				}
				cmd.Printf("retired keypair: kid=%s retired_at=%s; it leaves JWKS after KEYS_RETIREMENT_GRACE\n",
					kp.Kid, kp.RetiredAt.UTC().Format(time.RFC3339))
				return nil
			})
		},
	}
}

func newKeysListCmd(load deps[keysParams]) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List signing keypairs, oldest first, with their status",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			return load(ctx, func(p keysParams) error {
				if err := storeReady(ctx, p.Store); err != nil {
					return err
				}
				kps, err := p.Keys.Keypairs(ctx)
				if err != nil {
					return err
				}
				active, _ := keys.Active(kps)
				w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
				_, _ = fmt.Fprintln(w, "KID\tCREATED_AT\tSTATUS")
				for _, kp := range kps {
					status := "published"
					switch {
					case kp.Retired():
						status = "retired " + kp.RetiredAt.UTC().Format(time.RFC3339)
					case kp.Kid == active.Kid:
						status = "active"
					}
					_, _ = fmt.Fprintf(w, "%s\t%s\t%s\n", kp.Kid, kp.CreatedAt.UTC().Format(time.RFC3339), status)
				}
				return w.Flush()
			})
		},
	}
}

func newKeysGenerateCmd(load deps[keysParams]) *cobra.Command {
	var force bool
	c := &cobra.Command{
		Use:   "generate",
		Short: "Generate the JWT signing keypair (fails if one exists; use --force to rotate)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			return load(ctx, func(p keysParams) error {
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
			})
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
func newKeysEncryptCmd(load deps[keysParams]) *cobra.Command {
	return &cobra.Command{
		Use:   "encrypt",
		Short: "Encrypt stored signing keys with KEYS_ENCRYPTION_KEY (idempotent)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			return load(ctx, func(p keysParams) error {
				if err := storeReady(ctx, p.Store); err != nil {
					return err
				}
				n, err := p.Keys.EncryptStored(ctx, p.Store)
				if err != nil {
					return err
				}
				cmd.Printf("encrypted %d keypair(s)\n", n)
				return nil
			})
		},
	}
}
