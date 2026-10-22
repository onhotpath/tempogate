package perms

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type PermsSuite struct {
	suite.Suite
}

func TestPermsSuite(t *testing.T) {
	suite.Run(t, new(PermsSuite))
}

func (s *PermsSuite) TestRoleValid() {
	cases := []struct {
		name string
		role Role
		want bool
	}{
		{"read", RoleRead, true},
		{"write", RoleWrite, true},
		{"worker", RoleWorker, true},
		{"admin", RoleAdmin, true},
		{"empty", Role(""), false},
		{"unknown", Role("superuser"), false},
		{"wrong case", Role("ADMIN"), false},
	}

	for _, tc := range cases {
		s.Run(tc.name, func() {
			s.Equal(tc.want, tc.role.Valid())
		})
	}
}

func (s *PermsSuite) TestNewWithNoOptionsYieldsEmptyClaim() {
	g := New()

	claim := g.ToClaim()
	s.NotNil(claim, "ToClaim returns a non-nil empty slice so callers can pass it to a JWT builder unconditionally")
	s.Empty(claim)
}

func (s *PermsSuite) TestToClaimSingleNamespace() {
	g := New(AddNamespace("payments", RoleWorker))

	s.Equal([]string{"payments:worker"}, g.ToClaim())
}

func (s *PermsSuite) TestToClaimMultiNamespaceIsSortedByNamespace() {
	g := New(
		AddNamespace("tenant-a", RoleAdmin),
		AddNamespace("tenant-b", RoleRead),
	)

	// Deterministic order so test fixtures and golden diffs stay stable
	// across runs; without it map iteration would reshuffle the slice.
	s.Equal([]string{"tenant-a:admin", "tenant-b:read"}, g.ToClaim())
}

func (s *PermsSuite) TestToClaimSortingIsLexicographic() {
	g := New(
		AddNamespace("zeta", RoleRead),
		AddNamespace("alpha", RoleAdmin),
		AddNamespace("mu", RoleWrite),
	)

	s.Equal([]string{"alpha:admin", "mu:write", "zeta:read"}, g.ToClaim())
}

func (s *PermsSuite) TestWithSystemRoleEmitsTemporalSystemNamespace() {
	g := New(WithSystemRole(RoleAdmin))

	// The default Temporal ClaimMapper has no namespace wildcard:
	// cluster-wide access is granted by a permissions entry on
	// "temporal-system", which the authorizer ORs into every
	// namespace-scoped decision.
	s.Equal([]string{"temporal-system:admin"}, g.ToClaim())
}

func (s *PermsSuite) TestAddWildcardIsAliasOfWithSystemRole() {
	wildcardGrant := New(AddWildcard(RoleRead))
	systemGrant := New(WithSystemRole(RoleRead))

	// Both options write the same SystemNamespace entry; the only
	// difference is the call-site framing. Equality on the claim slice
	// pins that the two are interchangeable on the wire.
	s.Equal(systemGrant.ToClaim(), wildcardGrant.ToClaim())
	s.Equal([]string{"temporal-system:read"}, wildcardGrant.ToClaim())
}

func (s *PermsSuite) TestWildcardWithEveryRole() {
	cases := []struct {
		name string
		role Role
		want string
	}{
		{"read", RoleRead, "temporal-system:read"},
		{"write", RoleWrite, "temporal-system:write"},
		{"worker", RoleWorker, "temporal-system:worker"},
		{"admin", RoleAdmin, "temporal-system:admin"},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			g := New(AddWildcard(tc.role))
			s.Equal([]string{tc.want}, g.ToClaim())
		})
	}
}

func (s *PermsSuite) TestDuplicateNamespaceAppliesLastWriteWins() {
	g := New(
		AddNamespace("payments", RoleRead),
		AddNamespace("payments", RoleAdmin),
	)

	// Grant keeps one role per namespace (last write wins) so callers can
	// layer a default and override per-namespace. Temporal's default
	// ClaimMapper would instead OR duplicate entries, so Grant never emits
	// them.
	s.Equal([]string{"payments:admin"}, g.ToClaim())
}

func (s *PermsSuite) TestSystemRoleCollapsesWithExplicitNamespace() {
	g := New(
		WithSystemRole(RoleAdmin),
		AddNamespace(SystemNamespace, RoleRead),
	)

	// Both options key the same underlying namespace, so last-write-wins
	// applies across them. Pinned so a future refactor that introduces a
	// separate "system" slot fails this test.
	s.Equal([]string{"temporal-system:read"}, g.ToClaim())
}

func (s *PermsSuite) TestMixedSystemAndPerNamespaceEmitsBoth() {
	g := New(
		WithSystemRole(RoleRead),
		AddNamespace("payments", RoleAdmin),
	)

	s.Equal([]string{"payments:admin", "temporal-system:read"}, g.ToClaim())
}

func (s *PermsSuite) TestNamespacesReturnsSortedPairs() {
	g := New(
		AddNamespace("zeta", RoleRead),
		AddNamespace("alpha", RoleAdmin),
	)

	s.Equal([]NamespacePermission{
		{Namespace: "alpha", Role: RoleAdmin},
		{Namespace: "zeta", Role: RoleRead},
	}, g.Namespaces())
}

func (s *PermsSuite) TestParseClaimRoundTrip() {
	original := New(
		AddNamespace("tenant-a", RoleAdmin),
		AddNamespace("tenant-b", RoleRead),
		WithSystemRole(RoleWorker),
	)

	parsed, err := ParseClaim(original.ToClaim())
	s.Require().NoError(err)
	s.Equal(original.ToClaim(), parsed.ToClaim())
}

func (s *PermsSuite) TestParseClaimEmptyInput() {
	g, err := ParseClaim(nil)
	s.Require().NoError(err)
	s.Empty(g.ToClaim())

	g, err = ParseClaim([]string{})
	s.Require().NoError(err)
	s.Empty(g.ToClaim())
}

func (s *PermsSuite) TestParseClaimNamespaceContainingColon() {
	// Split-on-last-colon means a namespace name with a ':' inside
	// round-trips correctly. Pinned so a future regex-based parser does
	// not silently break this case.
	in := []string{"weird:ns:name:admin"}

	g, err := ParseClaim(in)
	s.Require().NoError(err)
	s.Equal(in, g.ToClaim())
}

func (s *PermsSuite) TestParseClaimDuplicateNamespaceLastWriteWins() {
	g, err := ParseClaim([]string{"payments:read", "payments:admin"})
	s.Require().NoError(err)

	s.Equal([]string{"payments:admin"}, g.ToClaim())
}

func (s *PermsSuite) TestParseClaimMalformedEntry() {
	_, err := ParseClaim([]string{"missing-separator"})
	s.Require().Error(err)
	s.ErrorIs(err, ErrMalformedEntry)
}

func (s *PermsSuite) TestParseClaimEmptyNamespace() {
	_, err := ParseClaim([]string{":admin"})
	s.Require().Error(err)
	s.ErrorIs(err, ErrEmptyNamespace)
}

func (s *PermsSuite) TestParseClaimUnknownRole() {
	_, err := ParseClaim([]string{"payments:superuser"})
	s.Require().Error(err)
	s.ErrorIs(err, ErrInvalidRole)
}

func (s *PermsSuite) TestParseClaimErrorIncludesEntryIndex() {
	// Index in the error message is what makes operator debugging
	// tractable: a misconfigured key with five entries should point at
	// the failing one.
	_, err := ParseClaim([]string{"ok:read", "ok:write", "broken"})
	s.Require().Error(err)
	s.ErrorIs(err, ErrMalformedEntry)
	s.Contains(err.Error(), "entry 2")
}
