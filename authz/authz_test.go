package authz_test

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/suite"
	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"

	"github.com/onhotpath/tempogate/authz"
	"github.com/onhotpath/tempogate/oidc"
	"github.com/onhotpath/tempogate/perms"
)

type PolicySuite struct {
	suite.Suite
}

func TestPolicySuite(t *testing.T) {
	suite.Run(t, new(PolicySuite))
}

func (s *PolicySuite) parse(rules []string, dflt string) *authz.Policy {
	p, err := authz.Parse(rules, dflt)
	s.Require().NoError(err)
	return p
}

func (s *PolicySuite) resolve(p *authz.Policy, email string) []string {
	g, err := p.Resolve(context.Background(), email)
	s.Require().NoError(err)
	return g.ToClaim()
}

func (s *PolicySuite) TestEmailRuleMatchesCaseInsensitively() {
	p := s.parse([]string{"email:Alice@Example.com=ns-a:read"}, "")

	s.Equal([]string{"ns-a:read"}, s.resolve(p, "alice@example.com"))
	s.Equal([]string{"ns-a:read"}, s.resolve(p, "ALICE@EXAMPLE.COM"))
	s.Empty(s.resolve(p, "bob@example.com"))
	s.Empty(s.resolve(p, "alice@example.com.evil"))
}

func (s *PolicySuite) TestDomainRuleMatchesTheEmailDomainExactly() {
	p := s.parse([]string{"domain:Example.com=ns-a:read"}, "")

	s.Equal([]string{"ns-a:read"}, s.resolve(p, "carol@EXAMPLE.com"))
	s.Empty(s.resolve(p, "carol@sub.example.com"), "subdomains are other domains")
	s.Empty(s.resolve(p, "carol@notexample.com"))
	s.Empty(s.resolve(p, "no-at-sign"))
}

func (s *PolicySuite) TestMatchingRulesUnionWithHighestRolePerNamespace() {
	p := s.parse([]string{
		"domain:example.com=orders:read, payments:read",
		"email:alice@example.com=orders:write",
		"email:bob@example.com=temporal-system:admin",
	}, "")

	s.Equal([]string{"orders:write", "payments:read"}, s.resolve(p, "alice@example.com"))
	s.Equal([]string{"orders:read", "payments:read", "temporal-system:admin"}, s.resolve(p, "bob@example.com"))
	s.Equal([]string{"orders:read", "payments:read"}, s.resolve(p, "carol@example.com"))
}

func (s *PolicySuite) TestDefaultAppliesOnlyWhenNoRuleMatches() {
	p := s.parse([]string{"email:alice@example.com=ns-a:read"}, " orders:read , payments:write ")

	s.Equal([]string{"ns-a:read"}, s.resolve(p, "alice@example.com"), "a matching rule replaces the default")
	s.Equal([]string{"orders:read", "payments:write"}, s.resolve(p, "carol@example.com"))
}

func (s *PolicySuite) TestNoMatchAndNoDefaultDenies() {
	p := s.parse([]string{"email:alice@example.com=ns-a:read"}, "")
	g, err := p.Resolve(context.Background(), "carol@example.com")
	s.Require().NoError(err)
	s.True(g.Empty())
}

func (s *PolicySuite) TestZeroPolicyDeniesEveryone() {
	var p authz.Policy
	s.False(p.Configured())
	s.Empty(s.resolve(&p, "alice@example.com"))
}

func (s *PolicySuite) TestConfigured() {
	s.False(s.parse(nil, "").Configured())
	s.False(s.parse(nil, "  ").Configured())
	s.True(s.parse([]string{"email:a@example.com=ns:read"}, "").Configured())
	s.True(s.parse(nil, "temporal-system:admin").Configured())
}

func (s *PolicySuite) TestExplainNamesTheMatchedRules() {
	p := s.parse([]string{
		"email:alice@example.com=ns-a:read",
		"email:bob@example.com=ns-b:read",
		"domain:example.com=ns-c:read",
	}, "ns-d:read")

	e := p.Explain(" Alice@Example.com ")
	s.Equal("alice@example.com", e.Email)
	s.False(e.Default)
	s.Require().Len(e.Matched, 2)
	s.Equal(0, e.Matched[0].Index)
	s.Equal("email:alice@example.com", e.Matched[0].Selector())
	s.Equal(2, e.Matched[1].Index)
	s.Equal("domain:example.com=ns-c:read", e.Matched[1].Raw)
	s.Equal([]string{"ns-a:read", "ns-c:read"}, e.Grant.ToClaim())

	e = p.Explain("dave@other.test")
	s.True(e.Default)
	s.Empty(e.Matched)
	s.Equal([]string{"ns-d:read"}, e.Grant.ToClaim())
}

func (s *PolicySuite) TestAccessors() {
	p := s.parse([]string{"email:alice@example.com=ns-a:read"}, "temporal-system:read")
	s.Len(p.Rules(), 1)
	s.Equal([]string{"temporal-system:read"}, p.Default().ToClaim())
	s.Equal(perms.RoleRead, authz.SystemRole(p.Default()))
	s.Equal(perms.Role(""), authz.SystemRole(p.Rules()[0].Grant))
}

func (s *PolicySuite) TestParseRejects() {
	cases := []struct {
		name  string
		rule  string
		wants string
	}{
		{"no equals", "email:alice@example.com", "want"},
		{"no selector kind", "alice@example.com=ns:read", "selector must be"},
		{"unknown selector", "user:alice=ns:read", `unknown selector "user"`},
		{"group not yet", "group:ops@example.com=ns:read", "group: rules are not supported yet"},
		{"email without at", "email:alice=ns:read", "is not an email address"},
		{"email without local part", "email:@example.com=ns:read", "is not an email address"},
		{"email with two ats", "email:a@b@example.com=ns:read", "is not an email address"},
		{"empty domain", "domain:=ns:read", "is not an email domain"},
		{"domain with at", "domain:a@example.com=ns:read", "is not an email domain"},
		{"no permissions", "email:alice@example.com=", "grants nothing"},
		{"worker", "email:alice@example.com=ns:worker", "worker grants nothing"},
		{"wildcard", "domain:example.com=*:admin", "is not a namespace wildcard"},
		{"malformed permission", "domain:example.com=ns", "entry must be"},
		{"empty", "", "want"},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			_, err := authz.Parse([]string{"email:ok@example.com=ns:read", tc.rule}, "")
			s.Require().ErrorIs(err, authz.ErrInvalidRule)
			s.Contains(err.Error(), tc.wants)
			s.Contains(err.Error(), "rule 1", "the error names the offending rule")
		})
	}
}

func (s *PolicySuite) TestParseRejectsBadDefault() {
	for _, dflt := range []string{"ns:worker", "*:read", "ns", "ns:owner"} {
		_, err := authz.Parse(nil, dflt)
		s.Require().Errorf(err, "default %q", dflt)
		s.Contains(err.Error(), "OIDC_AUTHZ_DEFAULT_PERMISSIONS")
	}
}

// fxLogs builds authz.Fx with the given configuration and returns the
// startup log and the policy it provided.
func (s *PolicySuite) fxLogs(rules []string, dflt, allowed, hosted string) (string, *authz.Policy, oidc.PermissionResolver) {
	var (
		buf bytes.Buffer
		pol *authz.Policy
		res oidc.PermissionResolver
	)
	app := fxtest.New(s.T(),
		authz.Fx(),
		fx.Supply(slog.New(slog.NewTextHandler(&buf, nil))),
		fx.Supply(
			fx.Annotate(rules, fx.ResultTags(`name:"oidc_authz_rules"`)),
			fx.Annotate(dflt, fx.ResultTags(`name:"oidc_authz_default_permissions"`)),
		),
		fx.Provide(
			fx.Annotate(func() string { return allowed }, fx.ResultTags(`name:"oidc_allowed_domains"`)),
			fx.Annotate(func() string { return hosted }, fx.ResultTags(`name:"oidc_allowed_hosted_domains"`)),
		),
		fx.Populate(&pol, &res),
	)
	app.RequireStart().RequireStop()
	return buf.String(), pol, res
}

func (s *PolicySuite) TestFxProvidesPolicyAsResolverAndLogsSystemGrants() {
	logs, pol, res := s.fxLogs([]string{
		"email:alice@example.com=ns-a:read",
		"email:bob@example.com=temporal-system:admin",
	}, "", "example.com", "example.com")

	s.Same(pol, res)
	s.Contains(logs, "authorization policy loaded")
	s.Contains(logs, "rules=2")
	s.Contains(logs, "system_grant_rules=1")
	s.Contains(logs, "system_grant_rule_indexes=[1]")
	s.NotContains(logs, "level=WARN")
}

func (s *PolicySuite) TestFxWarnsAboutTheLegacyEscapeHatch() {
	logs, _, _ := s.fxLogs(nil, "temporal-system:admin", "example.com", "example.com")
	s.Contains(logs, "level=WARN")
	s.Contains(logs, "every admitted user is cluster admin")

	logs, _, _ = s.fxLogs(nil, "temporal-system:read", "example.com", "example.com")
	s.Contains(logs, "every admitted user gets it on every namespace")
	s.Contains(logs, "role=read")
}

func (s *PolicySuite) TestFxWarnsAboutRulesThatCannotDoWhatTheySay() {
	logs, _, _ := s.fxLogs([]string{
		"email:alice@other.test=ns-a:read",
		"domain:example.com=ns-b:read",
	}, "", "example.com", "")

	s.Contains(logs, "authorization rule can never match")
	s.Contains(logs, "selector=email:alice@other.test")
	s.Contains(logs, "domain authorization rule without Workspace mode")
	s.Contains(logs, "selector=domain:example.com")
}

func (s *PolicySuite) TestFxFailsOnAnInvalidRule() {
	app := fx.New(
		authz.Fx(),
		fx.NopLogger,
		fx.Supply(slog.New(slog.DiscardHandler)),
		fx.Supply(
			fx.Annotate([]string{"email:alice@example.com=ns:worker"}, fx.ResultTags(`name:"oidc_authz_rules"`)),
			fx.Annotate("", fx.ResultTags(`name:"oidc_authz_default_permissions"`)),
		),
		fx.Provide(
			fx.Annotate(func() string { return "" }, fx.ResultTags(`name:"oidc_allowed_domains"`)),
			fx.Annotate(func() string { return "" }, fx.ResultTags(`name:"oidc_allowed_hosted_domains"`)),
		),
		fx.Invoke(func(*authz.Policy) {}),
	)
	s.Require().ErrorIs(app.Err(), authz.ErrInvalidRule)
}
