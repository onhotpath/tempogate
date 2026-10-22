// Package authz decides which Temporal permissions a signed-in person's access
// token carries. Admission (the Google sign-in, OIDC_ALLOWED_DOMAINS and
// Workspace mode) only says who may sign in; this package says what they may
// do, and denies by default: an identity no rule grants anything to gets no
// token at all.
//
// The policy is static configuration (OIDC_AUTHZ_RULES_<n>,
// OIDC_AUTHZ_DEFAULT_PERMISSIONS), parsed and validated once at startup, so
// resolving is a pure in-memory lookup that the refresh grant can repeat on
// every exchange. Integration keys do not go through it: each carries the one
// (namespace, role) the admin API minted it with.
//
// The package is server-only. It is wired by Fx from the server modules and
// is never imported by the lean CLI build.
package authz

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/onhotpath/tempogate/perms"
)

// UpgradeNote is where the errors below send an operator upgrading from the
// release in which every admitted user was cluster admin.
const UpgradeNote = "docs/configuration.md#upgrading-to-deny-by-default-authorization"

// ErrNoPolicy is the refusal `serve` stops with when neither rules nor a
// default are configured: an upgrade then fails at deploy time, not at the
// first sign-in.
var ErrNoPolicy = errors.New("authz: no authorization configured; every sign-in would be denied. " +
	"Grant permissions with OIDC_AUTHZ_RULES_<n> (e.g. OIDC_AUTHZ_RULES_0=\"email:alice@example.com=orders:write\"), " +
	"or keep the previous behaviour with OIDC_AUTHZ_DEFAULT_PERMISSIONS=temporal-system:admin; see " + UpgradeNote)

// ErrInvalidRule wraps every rule-syntax error, so callers can tell a
// configuration mistake from anything else.
var ErrInvalidRule = errors.New("authz: invalid rule")

type selectorKind string

const (
	selectEmail  selectorKind = "email"
	selectDomain selectorKind = "domain"
	// selectGroup is reserved for Google Workspace groups (D1-4); rules that
	// use it are refused for now rather than silently never matching.
	selectGroup selectorKind = "group"
)

// Rule is one parsed OIDC_AUTHZ_RULES entry: a selector and the permissions
// it grants. Index is its position in the configured list, which is how logs
// and `tempogate authz explain` name it.
type Rule struct {
	Index int
	Raw   string
	Grant *perms.Grant

	kind  selectorKind
	value string
}

// Selector renders the rule's selector in canonical (lower-case) form, e.g.
// "email:alice@example.com".
func (r Rule) Selector() string { return string(r.kind) + ":" + r.value }

func (r Rule) matches(email, domain string) bool {
	switch r.kind {
	case selectEmail:
		return r.value == email
	case selectDomain:
		return r.value == domain
	}
	return false
}

// Policy is the parsed authorization configuration. The zero value denies
// everyone. It is immutable after Parse, so it is safe for concurrent use.
type Policy struct {
	rules []Rule
	dflt  *perms.Grant
}

// Parse validates the configured rules and default permissions. Each rule is
// "<selector>=<permission>[,<permission>...]" where the selector is
// email:<address> or domain:<email domain>, matched case-insensitively, and
// each permission is "<namespace>:<role>" as perms.ParseConfig accepts it.
// defaultPermissions is a comma-separated permission list (empty for none).
//
// Parse does not refuse an empty policy: `gen-oas` and `authz explain` work
// without one, and Configured lets `serve` refuse it.
func Parse(rules []string, defaultPermissions string) (*Policy, error) {
	p := &Policy{dflt: perms.New()}
	for i, raw := range rules {
		r, err := parseRule(i, raw)
		if err != nil {
			return nil, err
		}
		p.rules = append(p.rules, r)
	}
	if strings.TrimSpace(defaultPermissions) != "" {
		g, err := perms.ParseConfig(strings.Split(defaultPermissions, ","))
		if err != nil {
			return nil, fmt.Errorf("authz: OIDC_AUTHZ_DEFAULT_PERMISSIONS: %w", err)
		}
		p.dflt = g
	}
	return p, nil
}

func parseRule(i int, raw string) (Rule, error) {
	invalid := func(format string, args ...any) error {
		return fmt.Errorf("%w %d %q: %s", ErrInvalidRule, i, raw, fmt.Sprintf(format, args...))
	}
	selector, permissions, ok := strings.Cut(strings.TrimSpace(raw), "=")
	if !ok {
		return Rule{}, invalid(`want "<selector>=<namespace>:<role>[,...]"`)
	}
	kind, value, ok := strings.Cut(strings.TrimSpace(selector), ":")
	if !ok {
		return Rule{}, invalid("selector must be email:<address> or domain:<domain>")
	}
	r := Rule{Index: i, Raw: raw, kind: selectorKind(strings.ToLower(strings.TrimSpace(kind))), value: strings.ToLower(strings.TrimSpace(value))}
	switch r.kind {
	case selectEmail:
		local, domain, ok := strings.Cut(r.value, "@")
		if !ok || local == "" || domain == "" || strings.Contains(domain, "@") {
			return Rule{}, invalid("%q is not an email address", value)
		}
	case selectDomain:
		if r.value == "" || strings.Contains(r.value, "@") {
			return Rule{}, invalid("%q is not an email domain", value)
		}
	case selectGroup:
		return Rule{}, invalid("group: rules are not supported yet; use email: or domain:")
	default:
		return Rule{}, invalid("unknown selector %q; use email: or domain:", kind)
	}
	if strings.TrimSpace(permissions) == "" {
		return Rule{}, invalid("grants nothing; list at least one <namespace>:<role>")
	}
	g, err := perms.ParseConfig(strings.Split(permissions, ","))
	if err != nil {
		return Rule{}, invalid("%v", err)
	}
	r.Grant = g
	return r, nil
}

// Configured reports whether any rule or a default exists. Without either
// every sign-in is denied, which `serve` treats as a misconfiguration.
func (p *Policy) Configured() bool {
	return len(p.rules) > 0 || !p.dflt.Empty()
}

// Rules returns the parsed rules in configuration order.
func (p *Policy) Rules() []Rule {
	return append([]Rule(nil), p.rules...)
}

// Default returns the permissions that apply when no rule matches (possibly
// empty).
func (p *Policy) Default() *perms.Grant {
	return perms.Merge(p.dflt)
}

// Resolve satisfies oidc.PermissionResolver: it returns the permissions the access
// token of the person signed in as email carries. An empty grant means the
// person gets no token. The error is always nil for static rules; it exists
// for resolvers that call out (Workspace groups), which must fail closed.
func (p *Policy) Resolve(_ context.Context, email string) (*perms.Grant, error) {
	return p.Explain(email).Grant, nil
}

// Explanation is how a Policy arrived at an identity's permissions.
type Explanation struct {
	Email   string
	Matched []Rule
	// Default is true when no rule matched and the default permissions
	// (possibly none) applied.
	Default bool
	Grant   *perms.Grant
}

// Explain resolves email and reports which rules matched: the union of every
// matching rule with the highest role per namespace, or the default
// permissions when none matched.
func (p *Policy) Explain(email string) Explanation {
	email = strings.ToLower(strings.TrimSpace(email))
	e := Explanation{Email: email}
	domain := emailDomain(email)
	var grants []*perms.Grant
	for _, r := range p.rules {
		if r.matches(email, domain) {
			e.Matched = append(e.Matched, r)
			grants = append(grants, r.Grant)
		}
	}
	if len(e.Matched) == 0 {
		e.Default = true
		grants = append(grants, p.dflt)
	}
	e.Grant = perms.Merge(grants...)
	return e
}

func emailDomain(email string) string {
	at := strings.LastIndexByte(email, '@')
	if at < 0 {
		return ""
	}
	return email[at+1:]
}

// SystemRole returns the role g grants on Temporal's every-namespace system
// namespace, or "" when it grants none.
func SystemRole(g *perms.Grant) perms.Role {
	for _, np := range g.Namespaces() {
		if np.Namespace == perms.SystemNamespace {
			return np.Role
		}
	}
	return ""
}
