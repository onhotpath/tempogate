package servercmd

import (
	"errors"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"go.uber.org/fx"

	"github.com/onhotpath/tempogate/authz"
)

type authzParams struct {
	fx.In

	Policy *authz.Policy

	AllowedDomains string `name:"oidc_allowed_domains"`
}

// requireAuthz refuses to serve without any authorization configured. Every
// sign-in would be denied, which after an upgrade from the "everyone is
// admin" release is a misconfiguration to stop at deploy time, not a policy.
func requireAuthz(p *authz.Policy) error {
	if !p.Configured() {
		return authz.ErrNoPolicy
	}
	return nil
}

// newAuthzCmd groups the authorization subcommands. They read the same
// configuration `serve` does (OIDC_AUTHZ_*, OIDC_ALLOWED_DOMAINS) and touch
// no state, so they answer what a running server with that configuration
// would decide.
func newAuthzCmd(load deps[authzParams]) *cobra.Command {
	root := &cobra.Command{
		Use:   "authz",
		Short: "Inspect the authorization rules (OIDC_AUTHZ_*)",
	}
	root.AddCommand(newAuthzExplainCmd(load))
	return root
}

func newAuthzExplainCmd(load deps[authzParams]) *cobra.Command {
	var email string
	c := &cobra.Command{
		Use:   "explain",
		Short: "Show which rules match an email and the permissions its access token would carry",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if strings.TrimSpace(email) == "" {
				return errors.New("--email must be non-empty")
			}
			return load(cmd.Context(), func(p authzParams) error {
				return explain(cmd, p, email)
			})
		},
	}
	c.Flags().StringVar(&email, "email", "", "the email to explain (case-insensitive)")
	_ = c.MarkFlagRequired("email")
	return c
}

func explain(cmd *cobra.Command, p authzParams, email string) error {
	e := p.Policy.Explain(email)
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintf(w, "email:\t%s\n", e.Email)
	if !domainAllowed(p.AllowedDomains, e.Email) {
		_, _ = fmt.Fprintf(w, "admission:\tdenied: the email domain is not in OIDC_ALLOWED_DOMAINS, so this person cannot sign in at all\n")
	}
	if e.Default {
		_, _ = fmt.Fprintf(w, "matched:\tno rule; OIDC_AUTHZ_DEFAULT_PERMISSIONS applies\n")
	}
	for i, r := range e.Matched {
		label := ""
		if i == 0 {
			label = "matched:"
		}
		_, _ = fmt.Fprintf(w, "%s\trule %d\t%s\n", label, r.Index, strings.TrimSpace(r.Raw))
	}
	claim := e.Grant.ToClaim()
	if len(claim) == 0 {
		_, _ = fmt.Fprintf(w, "permissions:\tnone: sign-in is denied (access_denied), no token is issued\n")
	} else {
		_, _ = fmt.Fprintf(w, "permissions:\t%s\n", strings.Join(claim, ","))
	}
	return w.Flush()
}

func domainAllowed(allowed, email string) bool {
	at := strings.LastIndexByte(email, '@')
	if at < 0 {
		return false
	}
	for _, d := range strings.Split(allowed, ",") {
		if strings.EqualFold(strings.TrimSpace(d), email[at+1:]) {
			return true
		}
	}
	return false
}
