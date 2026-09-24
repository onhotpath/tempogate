package oidc

import (
	"context"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/onhotpath/tempogate/keys"
)

// bearerPrefix is the case-insensitive scheme RFC 6750 §2.1 mandates on the
// Authorization header.
const bearerPrefix = "Bearer "

// emailClaim is the OIDC-standard end-user identifier tempogate stamps on
// human tokens (mirrors the keys package's claim name; duplicated as a
// literal so oidc does not reach into keys' unexported constants).
const emailClaim = "email"

// UserInfo serves GET /userinfo: the OIDC UserInfo endpoint. Temporal Web
// UI's OIDC client calls it after the code exchange and uses the response
// for the session's display name. It authenticates the caller solely by the
// Bearer JWT tempogate itself minted — there is no separate session store.
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
	raw, ok := bearerToken(in.Authorization)
	if !ok {
		return nil, huma.Error401Unauthorized("missing or malformed Authorization: Bearer header")
	}

	tok, err := u.verifier.Verify(ctx, raw)
	if err != nil {
		return nil, huma.Error401Unauthorized("the access token is invalid or expired")
	}

	sub, _ := tok.Subject()
	if sub == "" {
		// Every tempogate-minted token sets sub = the verified email; one
		// without a subject is not a user we can describe.
		return nil, huma.Error401Unauthorized("token has no subject")
	}

	email := ""
	if v, ok := tok.Field(emailClaim); ok {
		email, _ = v.(string)
	}

	return &userInfoOutput{Body: userInfoBody{
		Sub:   sub,
		Email: email,
		// tempogate only mints a token after Google asserted email_verified
		// and the domain gate passed (see callback). A valid tempogate JWT
		// therefore always represents a verified identity; there is no
		// authenticated-but-unverified state to report.
		EmailVerified: true,
		Name:          displayName(email, sub),
	}}, nil
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
// (v1 carries no name from Google), falling back to the subject.
func displayName(email, sub string) string {
	if at := strings.IndexByte(email, '@'); at > 0 {
		return email[:at]
	}
	if email != "" {
		return email
	}
	return sub
}
