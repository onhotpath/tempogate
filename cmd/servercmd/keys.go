package servercmd

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/fx"

	"github.com/onhotpath/tempogate/keys"
)

type keysParams struct {
	fx.In

	Store stateStore
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
			"refused unless --force is given.",
		// Kids are base64url thumbprints, so about one in 32 starts with '-'
		// and pflag would read it as a cluster of shorthand flags. RunE
		// parses the flags itself so such a kid works without `--`.
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			args, help, err := parseKidArgs(cmd, args)
			if err != nil {
				return err
			}
			if help {
				return cmd.Help()
			}
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

// kidPattern matches a kid as GenerateKeypair derives it: the unpadded
// base64url SHA-256 JWK thumbprint, always 43 characters.
var kidPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// parseKidArgs parses cmd's flags out of args, treating an argument that is
// not one of cmd's flags but has the shape of a kid as the positional kid
// even when it starts with '-'. Anything after `--` is positional, as usual,
// and a malformed flag still fails as an unknown flag. It reports help=true
// when -h/--help was given, and enforces exactly one kid. cmd must only have
// bool flags: a value given as a separate argument would be taken as a kid.
func parseKidArgs(cmd *cobra.Command, args []string) (_ []string, help bool, _ error) {
	var flags, positional []string
	for i, a := range args {
		if a == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if strings.HasPrefix(a, "-") && (isFlagArg(cmd, a) || !kidPattern.MatchString(a)) {
			flags = append(flags, a)
			continue
		}
		positional = append(positional, a)
	}
	fs := cmd.Flags()
	if err := fs.Parse(flags); err != nil {
		return nil, false, cmd.FlagErrorFunc()(cmd, err)
	}
	if help, _ := fs.GetBool("help"); help {
		return nil, true, nil
	}
	// pflag leaves a bare "-" as an argument.
	positional = append(positional, fs.Args()...)
	if err := cobra.ExactArgs(1)(cmd, positional); err != nil {
		return nil, false, err
	}
	return positional, false, nil
}

// isFlagArg reports whether a names one of cmd's flags: --name, --name=v, or
// a single-letter -x shorthand.
func isFlagArg(cmd *cobra.Command, a string) bool {
	if name, ok := strings.CutPrefix(a, "--"); ok {
		name, _, _ = strings.Cut(name, "=")
		return cmd.Flags().Lookup(name) != nil
	}
	return len(a) == 2 && cmd.Flags().ShorthandLookup(a[1:]) != nil
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
