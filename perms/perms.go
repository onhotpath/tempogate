// Package perms is the shared domain type tempogate uses to describe what a
// token can do, before that description is serialized into the JWT's
// `permissions` claim.
//
// Why a separate package: the two token-minting paths — the OIDC /token
// endpoint that issues human/CLI tokens, and the admin /admin/keys endpoint
// that issues backend integration keys — both need to produce the same wire
// shape for the `permissions` claim so a single JWKS+verifier handles every
// token uniformly. Putting the wire-format mapping here keeps the two callers
// honest: they can only express what perms.Grant can express, and only one
// place owns the `<namespace>:<role>` translation.
//
// # Cluster-wide / "every namespace" access
//
// Temporal's default JWT ClaimMapper does NOT recognise a literal `*` as a
// namespace wildcard — a `*:admin` entry would be parsed as permission on a
// namespace literally named "*" and rejected by the authorizer for any real
// namespace target. The actual mechanism the default ClaimMapper exposes is
// the special "temporal-system" namespace: a permissions entry of
// `temporal-system:<role>` is bitwise-ORed into claims.System, and the
// default authorizer evaluates every namespace-scoped call as
// `hasRole = claims.System | claims.Namespaces[target]`. So a system role at
// read, write or admin applies across every namespace at that level (worker
// alone authorizes nothing; see Role).
//
// Two equivalent options encode that mechanism: WithSystemRole(role) names
// it after the Temporal concept ("grant on the system namespace") and
// AddWildcard(role) is its `*` alias for callers who prefer the intuitive
// framing. They are not "two paths that happen to converge" — AddWildcard
// is literally implemented as `return WithSystemRole(role)`, and both end
// up writing the same SystemNamespace entry. ToClaim emits
// `temporal-system:<role>`; the `*` only appears in the Go API and never
// reaches Temporal, because Temporal would treat `*` as a literal
// namespace name and deny every real-namespace call.
//
// # One entry per namespace, carrying the highest role
//
// Temporal's default ClaimMapper ORs every entry for a namespace into one
// role bitmask (`role |= permissionToRole(...)` in extractPermissions, see
// https://github.com/temporalio/temporal/blob/v1.32.1/common/authorization/default_jwt_claim_mapper.go#L134-L143),
// and the default authorizer then compares that mask numerically against
// the role an API needs. Its documentation says duplicate entries are
// "overridden"; the source does not. Grant sidesteps the disagreement: it
// keeps one role per namespace, the highest one it was given, so ToClaim
// never emits two entries for one namespace and a claim means the same
// under either reading. Adding a namespace twice, Merge and ParseClaim all
// apply that rule.
package perms

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Role enumerates the four canonical actions the default Temporal
// authorizer recognises. The string values are stable: changing one would
// silently reshape authz for every token already in circulation, because
// they are concatenated into the `<namespace>:<role>` entries the default
// ClaimMapper parses.
//
// RoleWorker on its own authorizes no API: Temporal's worker bit is below
// the reader bit, and the default authorizer needs at least reader for
// every non-health-check call (task-queue polling is a write API). Workers
// need RoleWrite.
type Role string

const (
	RoleRead   Role = "read"
	RoleWrite  Role = "write"
	RoleWorker Role = "worker"
	RoleAdmin  Role = "admin"
)

// SystemNamespace is the namespace string Temporal's default ClaimMapper
// treats as "cluster-wide" — a permission entry under this namespace lands
// in claims.System rather than claims.Namespaces, and the default authorizer
// ORs it into every namespace-scoped decision.
const SystemNamespace = "temporal-system"

// Wildcard is the intuitive sentinel the Go API accepts to mean "every
// namespace". It does NOT appear in the serialized claim: AddWildcard maps
// it to SystemNamespace because that is the only construct Temporal's
// default ClaimMapper honours for cluster-wide access. Kept exported so
// callers can build Grants from external config (`{"namespace": "*"}`)
// without re-implementing the translation.
const Wildcard = "*"

// roleBits mirrors Temporal's role bitmask (Worker=1, Reader=2, Writer=4,
// Admin=8, see
// https://github.com/temporalio/temporal/blob/v1.32.1/common/authorization/roles.go#L9-L12).
// The authorizer compares the ORed mask numerically, so the highest bit a
// namespace carries is the role it effectively has.
var roleBits = map[Role]int{
	RoleWorker: 1,
	RoleRead:   2,
	RoleWrite:  4,
	RoleAdmin:  8,
}

// Valid reports whether r is one of the four canonical Temporal roles.
// Useful at API boundaries where the caller has a string and needs a 4xx
// vs. 5xx decision before constructing the Grant.
func (r Role) Valid() bool {
	_, ok := roleBits[r]
	return ok
}

// Grantable rejects a (namespace, role) pair that is well-formed but cannot
// authorize anything at a Temporal frontend running the default
// authorizer, so a grant an operator writes never silently does nothing:
//
//   - `*` is not a wildcard there; Temporal treats it as a namespace named
//     "*". SystemNamespace is the every-namespace grant.
//   - worker alone passes no check: the default authorizer requires at
//     least reader for every API but health checks, and task-queue polling
//     is a write API (getRequiredRole in
//     https://github.com/temporalio/temporal/blob/v1.32.1/common/authorization/default_authorizer.go#L67-L77).
//
// Tokens already minted are not affected; ParseClaim still accepts both.
func Grantable(namespace string, role Role) error {
	switch {
	case namespace == Wildcard:
		return ErrWildcardNamespace
	case role == RoleWorker:
		return ErrWorkerRole
	}
	return nil
}

// ErrInvalidRole, ErrEmptyNamespace, ErrMalformedEntry are the sentinels
// ParseClaim returns; ParseConfig and Grantable add ErrWorkerRole and
// ErrWildcardNamespace. They are exported so callers can map each to a
// precise error response.
var (
	ErrInvalidRole       = errors.New("perms: role must be one of read/write/worker/admin")
	ErrEmptyNamespace    = errors.New("perms: namespace must not be empty")
	ErrMalformedEntry    = errors.New("perms: entry must be \"<namespace>:<role>\"")
	ErrWorkerRole        = errors.New("perms: worker grants nothing under Temporal's default authorizer; use write")
	ErrWildcardNamespace = errors.New("perms: \"*\" is not a namespace wildcard in Temporal; use " + SystemNamespace + " to grant every namespace")
)

// NamespacePermission is the (Namespace, Role) pair Grant materializes
// internally. It is exported so external mappers (config loaders, admin
// API DTOs) can hand Grant a slice of pairs without redefining the shape.
type NamespacePermission struct {
	Namespace string
	Role      Role
}

// Grant is the mutable, options-built description of what a token may do.
// It is intentionally not safe for concurrent mutation — the only call
// sites build a Grant locally inside a request handler and call ToClaim
// once.
type Grant struct {
	perms map[string]Role
}

// Option configures a Grant under construction by New.
type Option func(*Grant)

// New builds a Grant from the given options. With zero options ToClaim
// returns an empty slice, which is appropriate when a token should carry
// no permissions claim entries (the default authorizer denies every
// namespace-scoped call in that case).
func New(opts ...Option) *Grant {
	g := &Grant{perms: make(map[string]Role)}
	for _, o := range opts {
		o(g)
	}
	return g
}

// AddNamespace grants role on the given namespace. Granting a namespace
// twice keeps the higher role (see the package doc).
func AddNamespace(namespace string, role Role) Option {
	return func(g *Grant) { g.add(namespace, role) }
}

func (g *Grant) add(namespace string, role Role) {
	if cur, ok := g.perms[namespace]; !ok || roleBits[role] > roleBits[cur] {
		g.perms[namespace] = role
	}
}

// Merge is the union of grants: every namespace any of them names, at the
// highest role any of them gives it. Nil grants are skipped, and the inputs
// are left untouched.
func Merge(grants ...*Grant) *Grant {
	out := New()
	for _, g := range grants {
		if g == nil {
			continue
		}
		for ns, role := range g.perms {
			out.add(ns, role)
		}
	}
	return out
}

// Empty reports whether g grants nothing, i.e. ToClaim would be empty. A
// nil Grant grants nothing.
func (g *Grant) Empty() bool {
	return g == nil || len(g.perms) == 0
}

// WithSystemRole grants role on Temporal's system namespace. The default
// ClaimMapper bitwise-ORs the role into claims.System and the default
// authorizer combines it with every namespace-scoped decision
// (`hasRole = claims.System | claims.Namespaces[target]`), so this is the
// "every namespace at <role>" mechanism. Named for the literal Temporal
// concept it maps to; see AddWildcard for the `*`-flavoured alias that
// delegates to this function unchanged.
func WithSystemRole(role Role) Option {
	return AddNamespace(SystemNamespace, role)
}

// AddWildcard is the intuitive `*` alias of WithSystemRole. The body is
// literally `return WithSystemRole(role)` — there is one mechanism
// Temporal honours for cluster-wide access (a permission entry under
// SystemNamespace), and both names produce exactly that.
func AddWildcard(role Role) Option {
	return WithSystemRole(role)
}

// Namespaces returns the underlying (namespace, role) pairs in the same
// sort order ToClaim emits, so callers can inspect or render a Grant
// without round-tripping through ToClaim+ParseClaim.
func (g *Grant) Namespaces() []NamespacePermission {
	if g == nil {
		return []NamespacePermission{}
	}
	out := make([]NamespacePermission, 0, len(g.perms))
	for ns, role := range g.perms {
		out = append(out, NamespacePermission{Namespace: ns, Role: role})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Namespace < out[j].Namespace })
	return out
}

// ToClaim produces the slice the default Temporal ClaimMapper expects
// under the `permissions` claim: `["<namespace>:<role>", ...]`. Order is
// stable (lexicographic by namespace) so test fixtures and golden diffs
// stay deterministic across runs. Empty Grant returns a non-nil empty
// slice so the caller can pass it directly into the JWT builder without a
// nil-vs-empty check.
func (g *Grant) ToClaim() []string {
	pairs := g.Namespaces()
	out := make([]string, len(pairs))
	for i, p := range pairs {
		out[i] = p.Namespace + ":" + string(p.Role)
	}
	return out
}

// ParseClaim is the inverse of ToClaim, intended for debugging tooling and
// tests (e.g. asserting a freshly minted JWT round-trips through the
// canonical representation). Each entry must be exactly
// `<namespace>:<role>`; the split happens on the LAST colon so a namespace
// name that itself contains `:` round-trips correctly. Duplicate
// namespaces keep the highest role, which is what Temporal's ORed bitmask
// amounts to.
func ParseClaim(claim []string) (*Grant, error) {
	g := New()
	for i, entry := range claim {
		idx := strings.LastIndex(entry, ":")
		if idx < 0 {
			return nil, fmt.Errorf("%w: entry %d %q", ErrMalformedEntry, i, entry)
		}
		namespace := entry[:idx]
		role := Role(entry[idx+1:])
		if namespace == "" {
			return nil, fmt.Errorf("%w: entry %d %q", ErrEmptyNamespace, i, entry)
		}
		if !role.Valid() {
			return nil, fmt.Errorf("%w: entry %d %q", ErrInvalidRole, i, entry)
		}
		g.add(namespace, role)
	}
	return g, nil
}

// ParseConfig parses a permission list an operator wrote in configuration:
// ParseClaim's grammar, surrounding spaces trimmed, plus Grantable on every
// entry, so a typo that would mint a grant Temporal ignores fails at
// startup instead of at the first denied call. A worker entry is refused
// even next to a higher role for the same namespace: it can only be a
// mistake.
func ParseConfig(entries []string) (*Grant, error) {
	trimmed := make([]string, len(entries))
	for i, e := range entries {
		trimmed[i] = strings.TrimSpace(e)
	}
	g, err := ParseClaim(trimmed)
	if err != nil {
		return nil, err
	}
	for i, entry := range trimmed {
		idx := strings.LastIndex(entry, ":")
		if err := Grantable(entry[:idx], Role(entry[idx+1:])); err != nil {
			return nil, fmt.Errorf("%w: entry %d %q", err, i, entry)
		}
	}
	return g, nil
}
