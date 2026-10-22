package admin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"go.uber.org/zap"

	"github.com/onhotpath/tempogate/internal/clock"
	"github.com/onhotpath/tempogate/oidc"
)

const (
	// SessionsPath and SessionsRevokePath are exported for the same reason
	// as KeysPath: tests and docs reference the registered strings.
	SessionsPath       = "/admin/sessions"
	SessionsRevokePath = "/admin/sessions/revoke"
)

// Sessions serves the HTTP twin of `tempogate sessions list/revoke`: one
// session is one sign-in, i.e. one refresh-token family. Revoking ends the
// family at the store, which /token consults on every refresh, so the next
// refresh fails with invalid_grant; access tokens already issued stay valid
// until they expire, because Temporal honours only exp and JWKS.
type Sessions struct {
	store  SessionStore
	logger *zap.Logger
	now    func() time.Time
}

// SessionsOption configures *Sessions.
type SessionsOption func(*Sessions)

// WithSessionsLogger sets the logger the audit trail is written to.
//
// Panics on nil for the same reason as WithLogger.
func WithSessionsLogger(l *zap.Logger) SessionsOption {
	if l == nil {
		panic("admin: WithSessionsLogger requires a non-nil logger")
	}
	return func(h *Sessions) { h.logger = l }
}

// NewSessions panics on a nil store so a wiring bug fails at startup rather
// than on the first request.
func NewSessions(store SessionStore, opts ...SessionsOption) *Sessions {
	if store == nil {
		panic("admin: NewSessions requires a non-nil store")
	}
	h := &Sessions{
		store:  store,
		logger: zap.NewNop(),
		now:    clock.Now,
	}
	for _, o := range opts {
		o(h)
	}
	return h
}

// sessionView never carries a token value or hash; the store does not read
// them for this path in the first place.
type sessionView struct {
	FamilyID       string    `json:"family_id" doc:"the session id; pass it to revoke as family_id"`
	ClientID       string    `json:"client_id"`
	Email          string    `json:"email"`
	Subject        string    `json:"subject" doc:"the token sub, <connector>:<upstream sub>, e.g. google:1234"`
	Connector      string    `json:"connector" doc:"the connector the user signed in through, e.g. google"`
	AuthTime       time.Time `json:"auth_time" doc:"when the user signed in; the session ends OIDC_REFRESH_MAX_LIFETIME later"`
	LastRotationAt time.Time `json:"last_rotation_at" doc:"when the live refresh token was minted"`
	ExpiresAt      time.Time `json:"expires_at" doc:"when the live refresh token expires unless rotated"`
}

type sessionListInput struct {
	Email   string `query:"email" doc:"only sessions of this email (case-insensitive)"`
	Subject string `query:"subject" doc:"only sessions of this token sub, <connector>:<upstream sub> (exact)"`
}

type sessionListOutput struct {
	Body struct {
		Items []sessionView `json:"items"`
	}
}

// sessionRevokeBody takes exactly one selector, like `sessions revoke`.
// Validation runs in the handler so every selector mistake is the same 400.
type sessionRevokeBody struct {
	Email    string `json:"email,omitempty" doc:"revoke every session of this email (case-insensitive)"`
	Subject  string `json:"subject,omitempty" doc:"revoke every session of this token sub, <connector>:<upstream sub> (exact)"`
	FamilyID string `json:"family_id,omitempty" doc:"revoke the session with this family id; 404 if no such session ever existed"`
}

type sessionRevokeInput struct {
	Body sessionRevokeBody
}

type sessionRevokeOutput struct {
	Body struct {
		Revoked int `json:"revoked" doc:"live sessions this call ended; 0 when they were already revoked or expired"`
	}
}

func (h *Sessions) Register(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "admin-list-sessions",
		Security:    adminSecurity,
		Method:      http.MethodGet,
		Path:        SessionsPath,
		Summary:     "List live sessions (never returns token values)",
		Tags:        []string{"admin"},
	}, h.list)

	huma.Register(api, huma.Operation{
		OperationID: "admin-revoke-sessions",
		Security:    adminSecurity,
		Method:      http.MethodPost,
		Path:        SessionsRevokePath,
		Summary:     "Revoke sessions by email, subject or family id (idempotent)",
		Description: "Takes exactly one of email, subject or family_id. The client's next refresh fails with " +
			"invalid_grant; access tokens already issued stay valid until they expire (OIDC_ACCESS_TOKEN_TTL).",
		Tags: []string{"admin"},
	}, h.revoke)
}

func (h *Sessions) list(ctx context.Context, in *sessionListInput) (*sessionListOutput, error) {
	f := SessionFilter{Email: in.Email}
	if in.Subject != "" {
		var err error
		if f.ConnectorID, f.Subject, err = parseSubject(in.Subject); err != nil {
			return nil, err
		}
	}
	rows, err := h.store.List(ctx, f, h.now())
	if err != nil {
		return nil, fmt.Errorf("admin: list sessions: %w", err)
	}
	out := &sessionListOutput{}
	out.Body.Items = make([]sessionView, 0, len(rows))
	for _, r := range rows {
		out.Body.Items = append(out.Body.Items, sessionView{
			FamilyID:       r.FamilyID,
			ClientID:       r.ClientID,
			Email:          r.Email,
			Subject:        oidc.TokenSubject(r.ConnectorID, r.Subject),
			Connector:      r.ConnectorID,
			AuthTime:       r.AuthTime,
			LastRotationAt: r.RotatedAt,
			ExpiresAt:      r.ExpiresAt,
		})
	}
	return out, nil
}

func (h *Sessions) revoke(ctx context.Context, in *sessionRevokeInput) (*sessionRevokeOutput, error) {
	n, err := h.revokeBy(ctx, in.Body)
	h.audit(ctx, in.Body, n, err)
	var se huma.StatusError
	switch {
	case err == nil:
		out := &sessionRevokeOutput{}
		out.Body.Revoked = n
		return out, nil
	case errors.Is(err, ErrSessionNotFound):
		return nil, huma.Error404NotFound("session not found")
	case errors.As(err, &se):
		return nil, err
	default:
		return nil, fmt.Errorf("admin: revoke sessions: %w", err)
	}
}

func (h *Sessions) revokeBy(ctx context.Context, b sessionRevokeBody) (int, error) {
	set := 0
	for _, v := range []string{b.Email, b.Subject, b.FamilyID} {
		if v != "" {
			set++
		}
	}
	// An empty selector would match nothing and report success.
	if set != 1 {
		return 0, huma.Error400BadRequest("exactly one of email, subject or family_id must be non-empty")
	}
	now := h.now()
	switch {
	case b.Email != "":
		return h.store.RevokeEmail(ctx, b.Email, now)
	case b.Subject != "":
		connectorID, subject, err := parseSubject(b.Subject)
		if err != nil {
			return 0, err
		}
		return h.store.RevokeSubject(ctx, connectorID, subject, now)
	default:
		return h.store.RevokeFamily(ctx, b.FamilyID, now)
	}
}

// parseSubject splits the token form operators copy from a token's sub.
func parseSubject(sub string) (connectorID, subject string, err error) {
	connectorID, subject, err = oidc.ParseTokenSubject(sub)
	if err != nil {
		return "", "", huma.Error400BadRequest("subject must be a token sub, <connector>:<upstream sub> (e.g. google:1234)")
	}
	return connectorID, subject, nil
}

// audit writes one line per revoke attempt that passed the guard: the
// selector, how many live sessions it ended and the caller's token
// fingerprint. Session tokens never reach it.
func (h *Sessions) audit(ctx context.Context, b sessionRevokeBody, revoked int, err error) {
	c := callerFrom(ctx)
	h.logger.Info("admin audit",
		zap.String("action", "revoke_sessions"),
		zap.String("outcome", auditOutcome(err)),
		zap.String("email", b.Email),
		zap.String("subject", b.Subject),
		zap.String("family_id", b.FamilyID),
		zap.Int("revoked", revoked),
		zap.String("caller", c.fingerprint),
		zap.String("remote_addr", c.remoteAddr),
	)
}
