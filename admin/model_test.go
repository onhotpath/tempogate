package admin

import (
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

type ModelSuite struct {
	suite.Suite
}

func TestModelSuite(t *testing.T) {
	suite.Run(t, new(ModelSuite))
}

func (s *ModelSuite) TestNewAppliesEveryOption() {
	exp := time.Date(2030, 6, 1, 0, 0, 0, 0, time.UTC)
	k := New(
		WithNamespace("payments"),
		WithRole(RoleWorker),
		WithOwner("svc-recon"),
		WithExpiresAt(&exp),
	)

	s.Equal("payments", k.Namespace)
	s.Equal(RoleWorker, k.Role)
	s.Equal("svc-recon", k.Owner)
	s.Require().NotNil(k.ExpiresAt)
	s.True(exp.Equal(*k.ExpiresAt))
}

func (s *ModelSuite) TestNewWithNoOptionsYieldsZeroValue() {
	k := New()

	s.Empty(k.Namespace)
	s.Empty(k.Owner)
	s.Empty(string(k.Role))
	s.Nil(k.ExpiresAt)
	s.Nil(k.RevokedAt)
}

func (s *ModelSuite) TestValidate() {
	cases := []struct {
		name    string
		key     *IntegrationKey
		wantErr error
	}{
		{
			name:    "valid read",
			key:     New(WithNamespace("ns"), WithRole(RoleRead), WithOwner("o")),
			wantErr: nil,
		},
		{
			name:    "valid write",
			key:     New(WithNamespace("ns"), WithRole(RoleWrite), WithOwner("o")),
			wantErr: nil,
		},
		{
			name:    "worker grants nothing",
			key:     New(WithNamespace("ns"), WithRole(RoleWorker), WithOwner("o")),
			wantErr: ErrWorkerRole,
		},
		{
			name:    "valid admin",
			key:     New(WithNamespace("ns"), WithRole(RoleAdmin), WithOwner("o")),
			wantErr: nil,
		},
		{
			name:    "empty namespace",
			key:     New(WithRole(RoleRead), WithOwner("o")),
			wantErr: ErrEmptyNamespace,
		},
		{
			name:    "empty owner",
			key:     New(WithNamespace("ns"), WithRole(RoleRead)),
			wantErr: ErrEmptyOwner,
		},
		{
			name:    "empty role",
			key:     New(WithNamespace("ns"), WithOwner("o")),
			wantErr: ErrInvalidRole,
		},
		{
			name:    "unknown role",
			key:     New(WithNamespace("ns"), WithRole(Role("superuser")), WithOwner("o")),
			wantErr: ErrInvalidRole,
		},
		{
			name:    "role with wrong case",
			key:     New(WithNamespace("ns"), WithRole(Role("READ")), WithOwner("o")),
			wantErr: ErrInvalidRole,
		},
	}

	for _, tc := range cases {
		s.Run(tc.name, func() {
			err := tc.key.Validate()
			if tc.wantErr == nil {
				s.Require().NoError(err)
				return
			}
			s.Require().ErrorIs(err, tc.wantErr)
		})
	}
}

func (s *ModelSuite) TestGrantSerializesToSingleNamespaceRoleEntry() {
	k := New(WithNamespace("payments"), WithRole(RoleWrite), WithOwner("svc"))
	s.Equal([]string{"payments:write"}, k.Grant().ToClaim())
}

func (s *ModelSuite) TestGrantSystemNamespaceRoundTrip() {
	// The "temporal-system" namespace is the default ClaimMapper's
	// cluster-wide hook; an integration key minted against it should
	// land in the JWT as `temporal-system:admin` so the verifier puts
	// the role into claims.System rather than claims.Namespaces.
	k := New(WithNamespace("temporal-system"), WithRole(RoleAdmin), WithOwner("svc"))
	s.Equal([]string{"temporal-system:admin"}, k.Grant().ToClaim())
}
