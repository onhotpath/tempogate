package admin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/onhotpath/tempogate/keys"
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
)

// Keys serves the four admin operations: mint, get-by-id, list, revoke. The
// JWT itself is minted via the injected Signer, so every key — service,
// integration, or otherwise — verifies under the same JWKS as a human token.
type Keys struct {
	registry     KeyRegistry
	signer       *keys.Signer
	hydrator     DenylistHydrator
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
// Validation runs in the handler so role / namespace / owner all surface the
// same 400 status with the same body shape; pushing it down to Huma's schema
// layer would split role into 422 while the others stayed at 400.
type createBody struct {
	Namespace string     `json:"namespace" doc:"Temporal namespace this key authorizes"`
	Role      string     `json:"role" doc:"one of read, write, worker, admin"`
	Owner     string     `json:"owner" doc:"human email or service-account name"`
	ExpiresAt *time.Time `json:"expires_at,omitempty" doc:"absolute expiry; omit for a long-lived key governed by revocation"`
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

func (h *Keys) Register(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID:   "admin-create-key",
		Method:        http.MethodPost,
		Path:          KeysPath,
		Summary:       "Mint a new integration key + JWT",
		Tags:          []string{"admin"},
		DefaultStatus: http.StatusCreated,
	}, h.create)

	huma.Register(api, huma.Operation{
		OperationID: "admin-get-key",
		Method:      http.MethodGet,
		Path:        KeysIDPath,
		Summary:     "Fetch integration-key metadata (never the JWT)",
		Tags:        []string{"admin"},
	}, h.get)

	huma.Register(api, huma.Operation{
		OperationID: "admin-list-keys",
		Method:      http.MethodGet,
		Path:        KeysPath,
		Summary:     "List integration keys (cursor-paginated, id-DESC)",
		Tags:        []string{"admin"},
	}, h.list)

	huma.Register(api, huma.Operation{
		OperationID:   "admin-delete-key",
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
	if err := k.Validate(); err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}

	id, err := h.newID()
	if err != nil {
		return nil, fmt.Errorf("admin: generate id: %w", err)
	}
	now := h.now()

	var ttl time.Duration
	if k.ExpiresAt != nil {
		ttl = k.ExpiresAt.Sub(now)
		if ttl <= 0 {
			return nil, huma.Error400BadRequest("expires_at must be in the future")
		}
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
	// MarkRevoked returns the jti regardless of whether this is the first
	// or a repeat revoke, so the denylist hydrate below runs on every call
	// without worrying about idempotency.
	jti, err := h.registry.MarkRevoked(ctx, in.ID)
	if err != nil {
		if errors.Is(err, ErrIntegrationKeyNotFound) {
			return nil, huma.Error404NotFound("integration key not found")
		}
		return nil, fmt.Errorf("admin: revoke integration key: %w", err)
	}
	if h.hydrator != nil {
		// Storage is already authoritative — MarkRevoked wrote the
		// jti_denylist row in the same transaction. The hydrate call only
		// shortens the window during which an in-process verifier cache
		// could still hold a stale "active" entry for this jti.
		h.hydrator.Hydrate(jti)
	}
	return &deleteOutput{Status: http.StatusNoContent}, nil
}
