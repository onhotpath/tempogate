package admin

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"go.uber.org/zap"

	"github.com/onhotpath/tempogate/redact"
)

// SecurityScheme is the OpenAPI security scheme name the admin operations
// declare and the Guard registers.
const SecurityScheme = "adminToken"

// fingerprintLen is how many hex chars of the matched digest identify the
// caller in logs: enough to tell rotated tokens apart, too few to matter if
// the log leaks (the full digest is already only a hash of the token).
const fingerprintLen = 8

// Guard authenticates the admin API: it refuses requests whose Host is not
// allowlisted (DNS rebinding) and requests without a bearer token whose
// SHA-256 matches a configured digest. It has no disabled mode: with no
// digests every guarded request gets 401.
type Guard struct {
	digests [][sha256.Size]byte
	exact   map[string]struct{}
	anyPort map[string]struct{}
	logger  *zap.Logger
}

// GuardOption configures a Guard.
type GuardOption func(*Guard)

// WithTokenDigests sets the SHA-256 digests of the accepted bearer tokens.
// See ParseTokenDigests for the configured form.
func WithTokenDigests(digests [][sha256.Size]byte) GuardOption {
	return func(g *Guard) { g.digests = digests }
}

// WithAllowedHosts sets the accepted Host header values. An entry with a port
// must match exactly; an entry without one matches that host on any port.
// Matching is case-insensitive.
func WithAllowedHosts(hosts []string) GuardOption {
	return func(g *Guard) {
		for _, h := range hosts {
			h = strings.ToLower(strings.TrimSpace(h))
			if _, _, err := net.SplitHostPort(h); err == nil {
				g.exact[h] = struct{}{}
				continue
			}
			g.anyPort[strings.Trim(h, "[]")] = struct{}{}
		}
	}
}

// WithGuardLogger sets the logger rejected requests are reported on.
//
// Panics on nil so a wiring mistake fails at construction.
func WithGuardLogger(l *zap.Logger) GuardOption {
	if l == nil {
		panic("admin: WithGuardLogger requires a non-nil logger")
	}
	return func(g *Guard) { g.logger = l }
}

// NewGuard builds a Guard. With no options it accepts no token and no Host.
func NewGuard(opts ...GuardOption) *Guard {
	g := &Guard{
		exact:   map[string]struct{}{},
		anyPort: map[string]struct{}{},
		logger:  zap.NewNop(),
	}
	for _, o := range opts {
		o(g)
	}
	return g
}

// ParseTokenDigests parses a comma-separated list of hex SHA-256 digests
// (ADMIN_TOKEN_SHA256). Empty entries are skipped, so "" yields no digests.
// Errors name the entry's position, never its value: an operator who pasted
// the raw token by mistake must not see it echoed into startup logs.
func ParseTokenDigests(csv string) ([][sha256.Size]byte, error) {
	var out [][sha256.Size]byte
	for i, entry := range strings.Split(csv, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		b, err := hex.DecodeString(entry)
		if err != nil || len(b) != sha256.Size {
			return nil, fmt.Errorf("admin: ADMIN_TOKEN_SHA256 entry %d is not a %d-char hex SHA-256 digest", i+1, 2*sha256.Size)
		}
		out = append(out, [sha256.Size]byte(b))
	}
	return out, nil
}

// Install adds the guard to api and declares the bearer scheme in its
// OpenAPI document. Huma captures middleware when an operation is
// registered, so only operations registered after Install are guarded.
func (g *Guard) Install(api huma.API) {
	oapi := api.OpenAPI()
	if oapi.Components.SecuritySchemes == nil {
		oapi.Components.SecuritySchemes = map[string]*huma.SecurityScheme{}
	}
	oapi.Components.SecuritySchemes[SecurityScheme] = &huma.SecurityScheme{
		Type:        "http",
		Scheme:      "bearer",
		Description: "Admin token whose SHA-256 is listed in ADMIN_TOKEN_SHA256.",
	}
	api.UseMiddleware(g.middleware(api))
}

func (g *Guard) middleware(api huma.API) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		// Host first: a rebinding page must not learn whether its guess at
		// a token was right.
		if !g.hostAllowed(ctx.Host()) {
			g.reject(api, ctx, http.StatusMisdirectedRequest, "host_not_allowed", "host not allowed")
			return
		}
		redact.Declare(ctx.Context(), redact.Secret, ctx.Header("Authorization"))
		token, ok := bearerToken(ctx.Header("Authorization"))
		redact.Declare(ctx.Context(), redact.Secret, token)
		switch {
		case len(g.digests) == 0:
			g.reject(api, ctx, http.StatusUnauthorized, "locked", "admin API is locked: no ADMIN_TOKEN_SHA256 configured")
			return
		case !ok:
			g.reject(api, ctx, http.StatusUnauthorized, "missing_credentials", "bearer token required")
			return
		}
		fp, ok := g.match(token)
		if !ok {
			g.reject(api, ctx, http.StatusUnauthorized, "invalid_token", "invalid bearer token")
			return
		}
		next(huma.WithValue(ctx, callerKey{}, caller{fingerprint: fp, remoteAddr: ctx.RemoteAddr()}))
	}
}

// match compares against every digest so the time taken does not reveal
// which rotation slot, if any, matched.
func (g *Guard) match(token string) (string, bool) {
	sum := sha256.Sum256([]byte(token))
	matched := -1
	for i := range g.digests {
		if subtle.ConstantTimeCompare(sum[:], g.digests[i][:]) == 1 && matched < 0 {
			matched = i
		}
	}
	if matched < 0 {
		return "", false
	}
	return hex.EncodeToString(g.digests[matched][:])[:fingerprintLen], true
}

func (g *Guard) hostAllowed(host string) bool {
	host = strings.ToLower(host)
	if _, ok := g.exact[host]; ok {
		return true
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	_, ok := g.anyPort[strings.Trim(host, "[]")]
	return ok
}

func (g *Guard) reject(api huma.API, ctx huma.Context, status int, reason, msg string) {
	g.logger.Warn("admin request rejected",
		zap.String("action", "authenticate"),
		zap.String("outcome", "denied"),
		zap.String("reason", reason),
		zap.String("method", ctx.Method()),
		zap.String("path", ctx.URL().Path),
		zap.String("host", ctx.Host()),
		zap.String("remote_addr", ctx.RemoteAddr()),
	)
	if status == http.StatusUnauthorized {
		ctx.SetHeader("WWW-Authenticate", `Bearer realm="tempogate-admin"`)
	}
	_ = huma.WriteErr(api, ctx, status, msg)
}

func bearerToken(header string) (string, bool) {
	scheme, token, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	return token, token != ""
}

type callerKey struct{}

// caller is the authenticated identity the guard hands to handlers for the
// audit log.
type caller struct {
	fingerprint string
	remoteAddr  string
}

func callerFrom(ctx context.Context) caller {
	c, _ := ctx.Value(callerKey{}).(caller)
	return c
}
