// Package admin exposes tempogate's backend-callable integration-key API: a
// service can POST to /admin/keys to mint a long-lived JWT scoped to a single
// namespace+role, retrieve metadata, and revoke. The package owns the
// IntegrationKey domain type, the four Huma operations, and the consumer-side
// store interface; the JWT itself is minted via keys.Signer so the claim
// shape stays uniform with human and CLI tokens.
//
// The routes mount on the main HTTP listener for now; a follow-up will split
// them onto a private listener so they are unreachable from the public
// internet. A separate follow-up will wire the jti returned by
// MarkIntegrationKeyRevoked into a verifier-side denylist so revocation
// takes effect on the hot path.
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

// ErrInvalidRole, ErrEmptyNamespace, ErrEmptyOwner are the sentinels Validate
// returns. They are exported so handlers can map each to a precise 400
// response and so the sqlite layer (which never receives user input directly)
// can stay free of validation concerns. ErrInvalidRole wraps perms.ErrInvalidRole
// so callers that already errors.Is against the perms-side sentinel keep
// working as the two packages converge.
var (
	ErrInvalidRole    = fmt.Errorf("admin: %w", perms.ErrInvalidRole)
	ErrEmptyNamespace = errors.New("admin: namespace is required")
	ErrEmptyOwner     = errors.New("admin: owner is required")
)

// IntegrationKey is the persistent record behind a single minted JWT. ID is a
// UUIDv7 stamped by the POST handler; JTI is the value the Signer embeds in
// the `jti` claim of the JWT — the future denylist will key on it, which is
// why MarkIntegrationKeyRevoked surfaces it. ExpiresAt nil means "no expiry
// — lifetime governed by revocation"; RevokedAt nil means "active".
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
// from. A nil value keeps the key long-lived: Signer.Mint with TTL=0 emits no
// `exp` claim, and revocation becomes the only way the key stops authorizing.
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
	return nil
}

// Grant builds the perms.Grant this key contributes to the JWT's
// `permissions` claim. Returning a Grant rather than a single
// "<ns>:<role>" string keeps the claim shape uniform with the OIDC
// /token path: both callers feed perms.Grant.ToClaim() into
// keys.MintRequest.Permissions, and perms is the only place that owns
// the wire-format mapping.
func (k *IntegrationKey) Grant() *perms.Grant {
	return perms.New(perms.AddNamespace(k.Namespace, k.Role))
}
