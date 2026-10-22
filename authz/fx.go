package authz

import (
	"log/slog"
	"strings"

	"go.uber.org/fx"

	"github.com/onhotpath/tempogate/oidc"
	"github.com/onhotpath/tempogate/perms"
)

type policyParams struct {
	fx.In

	Logger *slog.Logger

	Rules          []string `name:"oidc_authz_rules"`
	Default        string   `name:"oidc_authz_default_permissions"`
	AllowedDomains string   `name:"oidc_allowed_domains"`
	HostedDomains  string   `name:"oidc_allowed_hosted_domains"`
}

// newPolicy parses the policy, so a malformed rule fails graph construction,
// and logs what an operator should know about it at startup.
func newPolicy(p policyParams) (*Policy, error) {
	pol, err := Parse(p.Rules, p.Default)
	if err != nil {
		return nil, err
	}
	logPolicy(p.Logger, pol, domainSet(p.AllowedDomains), domainSet(p.HostedDomains) != nil)
	return pol, nil
}

// logPolicy reports the cluster-wide grants (they reach every namespace) and
// the rules that cannot do what they look like they do.
func logPolicy(logger *slog.Logger, p *Policy, allowed map[string]struct{}, workspaceMode bool) {
	const op = "authz"
	var systemRules []int
	for _, r := range p.rules {
		if SystemRole(r.Grant) != "" {
			systemRules = append(systemRules, r.Index)
		}
		domain := r.value
		if r.kind == selectEmail {
			domain = emailDomain(r.value)
		}
		if _, ok := allowed[domain]; !ok {
			logger.Warn("authorization rule can never match: its domain is not in OIDC_ALLOWED_DOMAINS, so nobody it selects can sign in",
				"op", op, "rule", r.Index, "selector", r.Selector())
		}
		if r.kind == selectDomain && !workspaceMode {
			logger.Warn("domain authorization rule without Workspace mode: a consumer Google account created for an address at this domain matches it too; "+
				"set OIDC_ALLOWED_HOSTED_DOMAINS",
				"op", op, "rule", r.Index, "selector", r.Selector())
		}
	}
	logger.Info("authorization policy loaded",
		"op", op,
		"rules", len(p.rules),
		"system_grant_rules", len(systemRules),
		"system_grant_rule_indexes", systemRules,
		"default_permissions", p.dflt.ToClaim(),
	)
	switch role := SystemRole(p.dflt); role {
	case "":
	case perms.RoleAdmin:
		logger.Warn("OIDC_AUTHZ_DEFAULT_PERMISSIONS grants temporal-system:admin: every admitted user is cluster admin",
			"op", op)
	default:
		logger.Warn("OIDC_AUTHZ_DEFAULT_PERMISSIONS grants a temporal-system role: every admitted user gets it on every namespace",
			"op", op, "role", string(role))
	}
}

func domainSet(raw string) map[string]struct{} {
	var set map[string]struct{}
	for _, d := range strings.Split(raw, ",") {
		if d = strings.ToLower(strings.TrimSpace(d)); d != "" {
			if set == nil {
				set = map[string]struct{}{}
			}
			set[d] = struct{}{}
		}
	}
	return set
}

// Fx provides the parsed *Policy, also as the oidc.PermissionResolver the token
// endpoint, the Google callback and the device verification page consult.
func Fx() fx.Option {
	return fx.Provide(
		fx.Annotate(
			newPolicy,
			fx.As(new(oidc.PermissionResolver)),
			fx.As(fx.Self()),
		),
	)
}
