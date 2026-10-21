package servercmd

import (
	"errors"
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
	var force bool
	c := &cobra.Command{
		Use:   "retire <kid>",
		Short: "Retire a signing keypair: it stops signing now and leaves JWKS after KEYS_RETIREMENT_GRACE",
		Long: "Retire a signing keypair. A running server stops signing with it within KEYS_RELOAD_INTERVAL " +
			"and drops it from /.well-known/jwks.json once KEYS_RETIREMENT_GRACE has passed; from then on " +
			"every token it signed, integration keys included, stops verifying at Temporal. " +
			"The only active keypair cannot be retired: run `tempogate keys generate --force` first. " +
			"Retiring the signing keypair while its replacement is still inside KEYS_PUBLISH_DELAY is " +
			"refused unless --force is given. A kid may start with '-': pass it after `--`.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			return load(ctx, func(p keysParams) error {
				if err := storeReady(ctx, p.Store); err != nil {
					return err
				}
				var opts []keys.RetireOption
				if force {
					opts = append(opts, keys.RetireForce())
				}
				kp, err := p.Keys.Retire(ctx, args[0], opts...)
				if errors.Is(err, keys.ErrReplacementPending) {
					return fmt.Errorf("%w; retry then, or pass --force if this key is compromised "+
						"(Temporal may reject new tokens until it next refreshes JWKS)", err)
				}
				if err != nil {
					return err
				}
				cmd.Printf("retired keypair: kid=%s retired_at=%s; it leaves JWKS after KEYS_RETIREMENT_GRACE\n",
					kp.Kid, kp.RetiredAt.UTC().Format(time.RFC3339))
				return nil
			})
		},
	}
	c.Flags().BoolVar(&force, "force", false,
		"retire the signing keypair even though its replacement is still inside KEYS_PUBLISH_DELAY")
	return c
}

func newKeysListCmd(load deps[keysParams]) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List signing keypairs, oldest first, with their status (signing, pending, published, retired)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			return load(ctx, func(p keysParams) error {
				if err := storeReady(ctx, p.Store); err != nil {
					return err
				}
				sts, err := p.Keys.Statuses(ctx)
				if err != nil {
					return err
				}
				w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
				_, _ = fmt.Fprintln(w, "KID\tCREATED_AT\tSTATUS")
				for _, st := range sts {
					status := "published"
					switch {
					case st.Retired():
						status = "retired " + st.RetiredAt.UTC().Format(time.RFC3339)
					case st.Signing:
						status = "signing"
					case st.ActivatesAt != nil:
						status = "pending, signs from " + st.ActivatesAt.UTC().Format(time.RFC3339)
					}
					_, _ = fmt.Fprintf(w, "%s\t%s\t%s\n", st.Kid, st.CreatedAt.UTC().Format(time.RFC3339), status)
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
				sts, err := p.Keys.Statuses(ctx)
				if err != nil {
					return err
				}
				for _, st := range sts {
					if st.Kid == kp.Kid && st.ActivatesAt != nil {
						cmd.Printf("published in JWKS now; signs from %s (KEYS_PUBLISH_DELAY), retire the old key after that\n",
							st.ActivatesAt.UTC().Format(time.RFC3339))
					}
				}
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
