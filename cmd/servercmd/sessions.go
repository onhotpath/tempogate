package servercmd

import (
	"context"
	"errors"
	"fmt"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/fx"

	"github.com/onhotpath/tempogate/state/sqlite"
)

type sessionsParams struct {
	fx.In

	Store *sqlite.Store
}

// newSessionsCmd lets an operator inspect and end refresh-token sessions
// (one per sign-in, i.e. per refresh-token family) directly on the state
// store, like `keys`. The admin API's /admin/sessions routes are its HTTP
// twin over the same store methods; keep the two surfaces equal.
func newSessionsCmd(load deps[sessionsParams]) *cobra.Command {
	root := &cobra.Command{
		Use:   "sessions",
		Short: "List and revoke refresh-token sessions",
	}
	root.AddCommand(newSessionsListCmd(load), newSessionsRevokeCmd(load))
	return root
}

func newSessionsListCmd(load deps[sessionsParams]) *cobra.Command {
	var f sqlite.RefreshSessionFilter
	c := &cobra.Command{
		Use:   "list",
		Short: "List live sessions (never prints token values)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			return load(ctx, func(p sessionsParams) error {
				if err := storeReady(ctx, p.Store); err != nil {
					return err
				}
				sessions, err := p.Store.ListRefreshSessions(ctx, f, time.Now().UTC())
				if err != nil {
					return err
				}
				w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
				_, _ = fmt.Fprintln(w, "FAMILY_ID\tCLIENT_ID\tEMAIL\tSUBJECT\tAUTH_TIME\tLAST_ROTATION\tEXPIRES_AT")
				for _, s := range sessions {
					_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
						s.FamilyID, s.ClientID, s.Email, s.Subject,
						rfc3339(s.AuthTime), rfc3339(s.RotatedAt), rfc3339(s.ExpiresAt))
				}
				return w.Flush()
			})
		},
	}
	c.Flags().StringVar(&f.Email, "email", "", "only sessions of this email (case-insensitive)")
	c.Flags().StringVar(&f.Subject, "subject", "", "only sessions of this Google subject (exact)")
	return c
}

func newSessionsRevokeCmd(load deps[sessionsParams]) *cobra.Command {
	var email, subject, family string
	c := &cobra.Command{
		Use:   "revoke",
		Short: "Revoke every session of a user (--email, --subject) or one session (--family)",
		Long: "Revoke refresh-token sessions. The client's next refresh fails with invalid_grant.\n" +
			"Access tokens already issued stay valid until they expire (OIDC_ACCESS_TOKEN_TTL).",
		RunE: func(cmd *cobra.Command, _ []string) error {
			// MarkFlagsOneRequired accepts an explicitly empty value, which
			// would otherwise match nothing and report success.
			if email == "" && subject == "" && family == "" {
				return errors.New("one of --email, --subject or --family must be non-empty")
			}
			ctx := cmd.Context()
			return load(ctx, func(p sessionsParams) error {
				if err := storeReady(ctx, p.Store); err != nil {
					return err
				}
				now := time.Now().UTC()
				var (
					n   int
					err error
				)
				switch {
				case email != "":
					n, err = p.Store.RevokeRefreshByEmail(ctx, email, now)
				case subject != "":
					n, err = p.Store.RevokeRefreshBySubject(ctx, subject, now)
				default:
					n, err = p.Store.RevokeRefreshFamily(ctx, family, now)
				}
				if err != nil {
					return err
				}
				cmd.Printf("revoked %d session(s)\n", n)
				return nil
			})
		},
	}
	c.Flags().StringVar(&email, "email", "", "revoke every session of this email (case-insensitive)")
	c.Flags().StringVar(&subject, "subject", "", "revoke every session of this Google subject (exact)")
	c.Flags().StringVar(&family, "family", "", "revoke the session with this family id (see `sessions list`); fails if no such session exists")
	c.MarkFlagsMutuallyExclusive("email", "subject", "family")
	c.MarkFlagsOneRequired("email", "subject", "family")
	return c
}

// storeReady refuses to touch a store that is unreachable or not yet
// migrated, mirroring `keys generate`.
func storeReady(ctx context.Context, s *sqlite.Store) error {
	if err := s.Ping(ctx); err != nil {
		return fmt.Errorf("state store unreachable: %w", err)
	}
	return s.IsCurrent(ctx)
}

func rfc3339(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}
