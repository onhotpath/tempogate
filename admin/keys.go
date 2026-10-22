package admin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/onhotpath/tempogate/keys"
	"github.com/onhotpath/tempogate/perms"
)

const (
	// KeysPath and KeysIDPath are exported so integration tests and any
	// future discovery surface can reference the same strings the handlers
	// register, keeping the two from drifting.
	KeysPath   = "/admin/keys"
	KeysIDPath = "/admin/keys/{id}"

	// defaultListLimit and maxListLimit bound the page size. Defaults live
	// on the handler so the store layer receives an already-validated
	// positive int and never has to second-guess input.
	defaultListLimit = 50
	maxListLimit     = 200

	// DefaultMaxTTL caps expires_at when ADMIN_KEYS_MAX_TTL is not set.
	DefaultMaxTTL = 90 * 24 * time.Hour
)

// Keys serves the four admin operations: mint, get-by-id, list, revoke. The
// JWT itself is minted via the injected Signer, so every key — service,
// integration, or otherwise — verifies under the same JWKS as a human token.
type Keys struct {
	registry     KeyRegistry
	signer       *keys.Signer
	hydrator     DenylistHydrator
	logger       *zap.Logger
	systemGrants bool
	maxTTL       time.Duration
	now          func() time.Time
	newID        func() (string, error)
	defaultLimit int
	maxLimit     int
}

// KeysOption configures the *Keys handler. Distinct from admin.Option (which
// configures an IntegrationKey under construction by New) so the two option
// spaces don't collide on the package-level identifier.
type KeysOption func(*Keys)

// WithClock swaps the clock the handler reads for CreatedAt stamps and for
// computing the JWT's TTL from an absolute ExpiresAt. For tests.
//
// Panics on nil so a wiring mistake fails at construction rather than
// surfacing as a nil-function call on the first request.
func WithClock(now func() time.Time) KeysOption {
	if now == nil {
		panic("admin: WithClock requires a non-nil clock")
	}
	return func(k *Keys) { k.now = now }
}

// WithIDGenerator swaps the function that mints the IntegrationKey's primary
// id. For tests; the production wiring uses uuid.NewV7 so the id is
// time-sortable and globally unique.
//
// Panics on nil for the same reason as WithClock.
func WithIDGenerator(fn func() (string, error)) KeysOption {
	if fn == nil {
		panic("admin: WithIDGenerator requires a non-nil generator")
	}
	return func(k *Keys) { k.newID = fn }
}

// WithDenylistHydrator wires the in-process verifier cache the DELETE
// handler nudges after a successful revoke. Nil-safe: the handler skips the
// hydrate call when no hydrator is configured, which keeps the test wiring
// (and tempogate processes that don't verify their own tokens) simple.
func WithDenylistHydrator(h DenylistHydrator) KeysOption {
	return func(k *Keys) { k.hydrator = h }
}

// WithLogger sets the logger the audit trail is written to.
//
// Panics on nil for the same reason as WithClock.
func WithLogger(l *zap.Logger) KeysOption {
	if l == nil {
		panic("admin: WithLogger requires a non-nil logger")
	}
	return func(k *Keys) { k.logger = l }
}

// WithSystemGrants permits minting keys for perms.SystemNamespace. Temporal
// ORs a system role into every namespace decision, so such a key is a
// cluster-wide credential; refusing it by default bounds what a leaked admin
// token can mint.
func WithSystemGrants(allow bool) KeysOption {
	return func(k *Keys) { k.systemGrants = allow }
}

// WithMaxTTL caps how far in the future a key's expires_at may lie. Temporal
// honours only exp and JWKS, never the revocation list, so the cap bounds how
// long a leaked key authorizes at Temporal unless its signing key is retired.
//
// Panics on a non-positive cap: that would refuse every key.
func WithMaxTTL(d time.Duration) KeysOption {
	if d <= 0 {
		panic("admin: WithMaxTTL requires a positive duration")
	}
	return func(k *Keys) { k.maxTTL = d }
}

// NewKeys wires the registry and signer the handler will call on every
// request. Both are required: a nil registry would NPE inside Save/ByID/etc.
// on the first call; a nil signer would NPE inside Mint. Panicking here turns
// a wiring bug into an immediate, obvious startup failure instead of a
// per-request crash that only surfaces in production traffic.
func NewKeys(registry KeyRegistry, signer *keys.Signer, opts ...KeysOption) *Keys {
	if registry == nil {
		panic("admin: NewKeys requires a non-nil registry")
	}
	if signer == nil {
		panic("admin: NewKeys requires a non-nil signer")
	}
	k := &Keys{
		registry:     registry,
		signer:       signer,
		logger:       zap.NewNop(),
		maxTTL:       DefaultMaxTTL,
		now:          func() time.Time { return time.Now().UTC() },
		newID:        defaultNewID,
		defaultLimit: defaultListLimit,
		maxLimit:     maxListLimit,
	}
	for _, o := range opts {
		o(k)
	}
	return k
}

func defaultNewID() (string, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return "", fmt.Errorf("admin: generate id: %w", err)
	}
	return id.String(), nil
}

type createInput struct {
	Body createBody
}

// createBody intentionally does not declare an OpenAPI `enum` on Role.
// Validation runs in the handler so a malformed role, namespace or owner all
// surface the same 400 status with the same body shape; pushing it down to
// Huma's schema layer would split role into 422 while the others stayed at
// 400. Only the well-formed but useless worker role is a 422 (see mint).
type createBody struct {
	Namespace string     `json:"namespace" doc:"Temporal namespace this key authorizes"`
	Role      string     `json:"role" doc:"one of read, write, admin (worker is refused: it grants nothing under Temporal's default authorizer)"`
	Owner     string     `json:"owner" doc:"human email or service-account name"`
	ExpiresAt *time.Time `json:"expires_at,omitempty" doc:"required absolute expiry, in the future and at most ADMIN_KEYS_MAX_TTL (default 90 days) from now; Temporal honours only exp, so revocation alone does not stop a key there"`
}

type createOutput struct {
	Status int
	Body   createResponse
}

type createResponse struct {
	ID        string     `json:"id"`
	JWT       string     `json:"jwt"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

type keyView struct {
	ID        string     `json:"id"`
	Namespace string     `json:"namespace"`
	Role      string     `json:"role"`
	Owner     string     `json:"owner"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

func viewOf(k IntegrationKey) keyView {
	return keyView{
		ID:        k.ID,
		Namespace: k.Namespace,
		Role:      string(k.Role),
		Owner:     k.Owner,
		CreatedAt: k.CreatedAt,
		ExpiresAt: k.ExpiresAt,
		RevokedAt: k.RevokedAt,
	}
}

type getInput struct {
	ID string `path:"id"`
}

type getOutput struct {
	Body keyView
}

type listInput struct {
	Owner     string `query:"owner"`
	Namespace string `query:"namespace"`
	Limit     int    `query:"limit" doc:"page size, 1..200, default 50"`
	Cursor    string `query:"cursor" doc:"opaque cursor from the previous response's next_cursor"`
}

type listOutput struct {
	Body listBody
}

type listBody struct {
	Items      []keyView `json:"items"`
	NextCursor string    `json:"next_cursor"`
}

type deleteInput struct {
	ID string `path:"id"`
}

type deleteOutput struct {
	Status int
}

// adminSecurity is the requirement every keys operation declares, so the
// generated admin OpenAPI documents that they need the bearer token.
var adminSecurity = []map[string][]string{{SecurityScheme: {}}}

func (h *Keys) Register(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID:   "admin-create-key",
		Security:      adminSecurity,
		Method:        http.MethodPost,
		Path:          KeysPath,
		Summary:       "Mint a new integration key + JWT",
		Tags:          []string{"admin"},
		DefaultStatus: http.StatusCreated,
	}, h.create)

	huma.Register(api, huma.Operation{
		OperationID: "admin-get-key",
		Security:    adminSecurity,
		Method:      http.MethodGet,
		Path:        KeysIDPath,
		Summary:     "Fetch integration-key metadata (never the JWT)",
		Tags:        []string{"admin"},
	}, h.get)

	huma.Register(api, huma.Operation{
		OperationID: "admin-list-keys",
		Security:    adminSecurity,
		Method:      http.MethodGet,
		Path:        KeysPath,
		Summary:     "List integration keys (cursor-paginated, id-DESC)",
		Tags:        []string{"admin"},
	}, h.list)

	huma.Register(api, huma.Operation{
		OperationID:   "admin-delete-key",
		Security:      adminSecurity,
		Method:        http.MethodDelete,
		Path:          KeysIDPath,
		Summary:       "Revoke an integration key (soft delete, idempotent)",
		Tags:          []string{"admin"},
		DefaultStatus: http.StatusNoContent,
	}, h.delete)
}

func (h *Keys) create(ctx context.Context, in *createInput) (*createOutput, error) {
	k := New(
		WithNamespace(in.Body.Namespace),
		WithRole(Role(in.Body.Role)),
		WithOwner(in.Body.Owner),
		WithExpiresAt(in.Body.ExpiresAt),
	)
	out, err := h.mint(ctx, k)
	h.audit(ctx, "create", auditOutcome(err), *k)
	return out, err
}

func (h *Keys) mint(ctx context.Context, k *IntegrationKey) (*createOutput, error) {
	if err := k.Validate(); errors.Is(err, ErrWorkerRole) {
		// A well-formed request for a key that would authorize nothing:
		// 422 tells the caller to change the role, not fix the syntax.
		return nil, huma.Error422UnprocessableEntity(err.Error())
	} else if err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}
	if k.Namespace == perms.SystemNamespace && !h.systemGrants {
		return nil, huma.Error403Forbidden(perms.SystemNamespace +
			" grants are cluster-wide and disabled; set ADMIN_ALLOW_SYSTEM_GRANTS=true to allow them")
	}

	id, err := h.newID()
	if err != nil {
		return nil, fmt.Errorf("admin: generate id: %w", err)
	}
	now := h.now()

	// Checked here rather than in Validate: the rule needs the handler's
	// clock and cap, and stored keys minted before expiry was required
	// legitimately have none.
	if k.ExpiresAt == nil {
		return nil, huma.Error400BadRequest("expires_at is required")
	}
	ttl := k.ExpiresAt.Sub(now)
	if ttl <= 0 {
		return nil, huma.Error400BadRequest("expires_at must be in the future")
	}
	if ttl > h.maxTTL {
		return nil, huma.Error400BadRequest(fmt.Sprintf("expires_at must be at most %s from now (ADMIN_KEYS_MAX_TTL)", h.maxTTL))
	}

	signed, jti, err := h.signer.Mint(ctx, keys.MintRequest{
		Subject:     k.Owner,
		Permissions: k.Grant().ToClaim(),
		TTL:         ttl,
	})
	if err != nil {
		return nil, fmt.Errorf("admin: mint jwt: %w", err)
	}

	k.ID = id
	k.JTI = jti
	k.CreatedAt = now

	if err := h.registry.Save(ctx, *k); err != nil {
		return nil, fmt.Errorf("admin: save integration key: %w", err)
	}

	return &createOutput{
		Status: http.StatusCreated,
		Body: createResponse{
			ID:        id,
			JWT:       signed,
			ExpiresAt: k.ExpiresAt,
		},
	}, nil
}

func (h *Keys) get(ctx context.Context, in *getInput) (*getOutput, error) {
	row, err := h.registry.ByID(ctx, in.ID)
	if errors.Is(err, ErrIntegrationKeyNotFound) {
		return nil, huma.Error404NotFound("integration key not found")
	}
	if err != nil {
		return nil, fmt.Errorf("admin: get integration key: %w", err)
	}
	return &getOutput{Body: viewOf(row)}, nil
}

func (h *Keys) list(ctx context.Context, in *listInput) (*listOutput, error) {
	limit := in.Limit
	switch {
	case limit <= 0:
		limit = h.defaultLimit
	case limit > h.maxLimit:
		limit = h.maxLimit
	}

	if in.Cursor != "" {
		if _, err := uuid.Parse(in.Cursor); err != nil {
			return nil, huma.Error400BadRequest("cursor is not a valid id")
		}
	}

	rows, err := h.registry.List(ctx, ListFilter{
		Owner:     in.Owner,
		Namespace: in.Namespace,
		Limit:     limit,
		Cursor:    in.Cursor,
	})
	if err != nil {
		return nil, fmt.Errorf("admin: list integration keys: %w", err)
	}

	body := listBody{Items: make([]keyView, 0, limit)}
	if len(rows) > limit {
		// The store returned limit+1 to signal "more". The first `limit`
		// rows form the page; the (limit+1)-th is dropped from the response
		// and its predecessor's id becomes the next cursor.
		for _, r := range rows[:limit] {
			body.Items = append(body.Items, viewOf(r))
		}
		body.NextCursor = rows[limit-1].ID
	} else {
		for _, r := range rows {
			body.Items = append(body.Items, viewOf(r))
		}
	}

	return &listOutput{Body: body}, nil
}

func (h *Keys) delete(ctx context.Context, in *deleteInput) (*deleteOutput, error) {
	jti, err := h.revoke(ctx, in.ID)
	row := IntegrationKey{ID: in.ID, JTI: jti}
	if err == nil {
		// Read back only so the audit line can say what was revoked; a
		// failure here must not turn a completed revoke into an error.
		if got, gerr := h.registry.ByID(ctx, in.ID); gerr == nil {
			row = got
		}
	}
	h.audit(ctx, "revoke", auditOutcome(err), row)
	switch {
	case err == nil:
		return &deleteOutput{Status: http.StatusNoContent}, nil
	case errors.Is(err, ErrIntegrationKeyNotFound):
		return nil, huma.Error404NotFound("integration key not found")
	default:
		return nil, fmt.Errorf("admin: revoke integration key: %w", err)
	}
}

func (h *Keys) revoke(ctx context.Context, id string) (string, error) {
	// MarkRevoked returns the jti regardless of whether this is the first
	// or a repeat revoke, so the denylist hydrate below runs on every call
	// without worrying about idempotency.
	jti, err := h.registry.MarkRevoked(ctx, id)
	if err != nil {
		return "", err
	}
	if h.hydrator != nil {
		// Storage is already authoritative — MarkRevoked wrote the
		// jti_denylist row in the same transaction. The hydrate call only
		// shortens the window during which an in-process verifier cache
		// could still hold a stale "active" entry for this jti.
		h.hydrator.Hydrate(jti)
	}
	return jti, nil
}

// audit writes one line per mint or revoke attempt that passed the guard.
// It carries ids and the caller's token fingerprint, never a token or JWT.
func (h *Keys) audit(ctx context.Context, action, outcome string, k IntegrationKey) {
	c := callerFrom(ctx)
	h.logger.Info("admin audit",
		zap.String("action", action),
		zap.String("outcome", outcome),
		zap.String("id", k.ID),
		zap.String("jti", k.JTI),
		zap.String("namespace", k.Namespace),
		zap.String("role", string(k.Role)),
		zap.String("owner", k.Owner),
		zap.String("caller", c.fingerprint),
		zap.String("remote_addr", c.remoteAddr),
	)
}

func auditOutcome(err error) string {
	var se huma.StatusError
	switch {
	case err == nil:
		return "success"
	case errors.Is(err, ErrIntegrationKeyNotFound), errors.Is(err, ErrSessionNotFound):
		return "not_found"
	case errors.As(err, &se) && se.GetStatus() == http.StatusForbidden:
		return "denied"
	case errors.As(err, &se) && se.GetStatus() == http.StatusBadRequest:
		return "invalid"
	default:
		return "error"
	}
}
