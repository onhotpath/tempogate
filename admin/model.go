// Package admin exposes tempogate's backend-callable integration-key API: a
// service can POST to /admin/keys to mint an expiring JWT scoped to a single
// namespace+role, retrieve metadata, and revoke. It also lists and retires
// the signing keys those JWTs are signed with (/admin/signing-keys). The
// package owns the IntegrationKey domain type, the Huma operations, and the
// consumer-side store interface; the JWT itself is minted via keys.Signer so
// the claim shape stays uniform with human and CLI tokens.
//
// The routes mount only on the private admin listener (ADMIN_LISTENER), never
// on the public OIDC listener, and every request passes the Guard (admin
// token digest plus Host allowlist). Revoking a key records its jti in the
// denylist that keys.Verifier consults, so tempogate's own endpoints reject
// it within the denylist cache TTL. Temporal never sees that denylist: at
// Temporal a key works until its exp, or until its signing key is retired
// and its kid has left JWKS.
package admin

import (
	"errors"
	"fmt"
	"time"

	"github.com/onhotpath/tempogate/perms"
)

// Role aliases perms.Role so admin-package callers keep using the local
// name (admin.Role, admin.RoleAdmin, …) while the canonical definition
// lives in perms — the shared package the OIDC /token endpoint also
// consumes. An alias is enough: the underlying type is identical, so a
// value built with admin.RoleAdmin satisfies perms.Role anywhere a
// perms.Grant or perms.AddNamespace call is constructed.
type Role = perms.Role

const (
	RoleRead   = perms.RoleRead
	RoleWrite  = perms.RoleWrite
	RoleWorker = perms.RoleWorker
	RoleAdmin  = perms.RoleAdmin
)

// ErrInvalidRole, ErrWorkerRole, ErrEmptyNamespace, ErrEmptyOwner are the
// sentinels Validate returns. They are exported so handlers can map each to a
// precise response and so the sqlite layer (which never receives user input
// directly) can stay free of validation concerns. The role sentinels wrap
// their perms-side counterparts so callers that already errors.Is against
// those keep working as the two packages converge.
var (
	ErrInvalidRole    = fmt.Errorf("admin: %w", perms.ErrInvalidRole)
	ErrWorkerRole     = fmt.Errorf("admin: %w", perms.ErrWorkerRole)
	ErrEmptyNamespace = errors.New("admin: namespace is required")
	ErrEmptyOwner     = errors.New("admin: owner is required")
)

// IntegrationKey is the persistent record behind a single minted JWT. ID is a
// UUIDv7 stamped by the POST handler; JTI is the value the Signer embeds in
// the `jti` claim of the JWT — the future denylist will key on it, which is
// why MarkIntegrationKeyRevoked surfaces it. New keys always carry ExpiresAt;
// nil only appears on rows minted before expiry was required, whose JWT has no
// exp and stays valid at Temporal until its signing key is retired. RevokedAt
// nil means "active".
type IntegrationKey struct {
	ID        string
	Namespace string
	Role      Role
	Owner     string
	JTI       string
	CreatedAt time.Time
	ExpiresAt *time.Time
	RevokedAt *time.Time
}

// Option configures an IntegrationKey under construction by New. Only the
// caller-supplied fields are exposed as options: ID, JTI, and CreatedAt are
// stamped by the POST handler after validation succeeds, and RevokedAt is
// owned by MarkRevoked.
type Option func(*IntegrationKey)

func WithNamespace(ns string) Option { return func(k *IntegrationKey) { k.Namespace = ns } }

func WithRole(r Role) Option { return func(k *IntegrationKey) { k.Role = r } }

func WithOwner(o string) Option { return func(k *IntegrationKey) { k.Owner = o } }

// WithExpiresAt sets the absolute expiry the JWT's `exp` claim is derived
// from. The POST handler refuses nil: Temporal ignores revocation, so a key
// without `exp` could only be stopped there by retiring its signing key.
func WithExpiresAt(t *time.Time) Option { return func(k *IntegrationKey) { k.ExpiresAt = t } }

// New builds a fresh IntegrationKey from the caller-supplied options. It does
// not stamp ID/CreatedAt/JTI — those are set by the POST handler once
// Validate passes and the Signer has minted the JWT — so calling Validate on
// a New-returned value exercises only the input fields the user controls.
func New(opts ...Option) *IntegrationKey {
	k := &IntegrationKey{}
	for _, o := range opts {
		o(k)
	}
	return k
}

// Validate checks the caller-supplied fields against the rules the POST
// handler enforces before persisting. It is intentionally independent of
// ID/CreatedAt/JTI: those are server-stamped and validating them here would
// either require the handler to call Validate after stamping (changing the
// error-mapping shape) or duplicate the rule across two call sites.
//
// A worker key is refused (ErrWorkerRole): under Temporal's default
// authorizer it passes no check (see perms.Grantable), so minting one would
// hand out a credential that only fails later, at Temporal. Keys stored
// before this rule keep their role.
func (k *IntegrationKey) Validate() error {
	if k.Namespace == "" {
		return ErrEmptyNamespace
	}
	if k.Owner == "" {
		return ErrEmptyOwner
	}
	if !k.Role.Valid() {
		return ErrInvalidRole
	}
	if k.Role == RoleWorker {
		return ErrWorkerRole
	}
	return nil
}

// Grant builds the perms.Grant this key contributes to the JWT's
// `permissions` claim. Returning a Grant rather than a single
// "<ns>:<role>" string keeps perms the only place that owns the
// wire-format mapping. The OIDC /token path builds its claim from a
// perms.Grant too, resolved per person by the authz rules; integration keys
// do not go through those rules.
func (k *IntegrationKey) Grant() *perms.Grant {
	return perms.New(perms.AddNamespace(k.Namespace, k.Role))
}
