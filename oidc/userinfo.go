package oidc

import (
	"context"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/lestrrat-go/jwx/v4/jwt"

	"github.com/onhotpath/tempogate/keys"
	"github.com/onhotpath/tempogate/redact"
)

// bearerPrefix is the case-insensitive scheme RFC 6750 §2.1 mandates on the
// Authorization header.
const bearerPrefix = "Bearer "

// emailClaim is the OIDC-standard end-user identifier tempogate stamps on
// human tokens, and idpClaim the connector the person signed in through
// (mirroring the keys package's claim names; duplicated as literals so oidc
// does not reach into keys' unexported constants).
const (
	emailClaim = "email"
	idpClaim   = "idp"
)

// UserInfo serves GET /userinfo: the OIDC UserInfo endpoint, a protected
// resource (OIDC Core §5.3). Temporal Web UI's OIDC client calls it after the
// code exchange and uses the response for the session's display name. It
// authenticates the caller solely by a Bearer access token tempogate itself
// minted - there is no separate session store. The Verifier accepts access
// tokens for the configured Temporal audience only, so an ID token, a token
// for another audience, or one minted before access tokens were typed is
// refused. Integration keys are access tokens too; the Verifier's denylist
// check is what makes their revocation visible here.
type UserInfo struct {
	verifier *keys.Verifier
}

func NewUserInfo(verifier *keys.Verifier) *UserInfo {
	return &UserInfo{verifier: verifier}
}

type userInfoInput struct {
	Authorization string `header:"Authorization" doc:"Bearer <tempogate-issued JWT>"`
}

type userInfoBody struct {
	Sub           string `json:"sub"`
	IDP           string `json:"idp,omitempty"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
}

type userInfoOutput struct {
	Body userInfoBody
}

func (u *UserInfo) Register(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "userinfo",
		Method:      http.MethodGet,
		Path:        UserInfoPath,
		Summary:     "OIDC UserInfo endpoint (Bearer-authenticated)",
		Tags:        []string{"oidc"},
	}, func(ctx context.Context, in *userInfoInput) (*userInfoOutput, error) {
		return u.handle(ctx, in)
	})
}

func (u *UserInfo) handle(ctx context.Context, in *userInfoInput) (*userInfoOutput, error) {
	redact.Declare(ctx, redact.Secret, in.Authorization)
	raw, ok := bearerToken(in.Authorization)
	redact.Declare(ctx, redact.Secret, raw)
	if !ok {
		return nil, huma.Error401Unauthorized("missing or malformed Authorization: Bearer header")
	}

	tok, err := u.verifier.Verify(ctx, raw)
	if err != nil {
		return nil, huma.Error401Unauthorized("the access token is invalid or expired")
	}

	sub, _ := tok.Subject()
	if sub == "" {
		// Every tempogate-minted human token sets sub =
		// <connector>:<upstream subject>; one without a subject is not a
		// user we can describe.
		return nil, huma.Error401Unauthorized("token has no subject")
	}

	email, idp := stringClaim(tok, emailClaim), stringClaim(tok, idpClaim)
	declareIdentity(ctx, sub, email)

	return &userInfoOutput{Body: userInfoBody{
		Sub:   sub,
		IDP:   idp,
		Email: email,
		// tempogate only mints a token after Google asserted email_verified
		// and the domain gate passed (see callback). A valid tempogate JWT
		// therefore always represents a verified identity; there is no
		// authenticated-but-unverified state to report.
		EmailVerified: true,
		Name:          displayName(email, sub),
	}}, nil
}

// stringClaim is the claim's value, or "" when it is absent or not a string.
func stringClaim(tok jwt.Token, name string) string {
	v, _ := tok.Field(name)
	s, _ := v.(string)
	return s
}

// bearerToken extracts the credential from an "Authorization: Bearer <jwt>"
// header. The scheme match is case-insensitive per RFC 6750; an empty or
// missing token yields ok=false so the handler answers 401 uniformly.
func bearerToken(header string) (string, bool) {
	if len(header) <= len(bearerPrefix) ||
		!strings.EqualFold(header[:len(bearerPrefix)], bearerPrefix) {
		return "", false
	}
	tok := strings.TrimSpace(header[len(bearerPrefix):])
	if tok == "" {
		return "", false
	}
	return tok, true
}

// displayName derives the session label: the email local-part when present
// (v1 carries no name from Google), falling back to the subject, which is an
// opaque account id for human tokens and the owner for integration keys.
func displayName(email, sub string) string {
	if at := strings.IndexByte(email, '@'); at > 0 {
		return email[:at]
	}
	if email != "" {
		return email
	}
	return sub
}
