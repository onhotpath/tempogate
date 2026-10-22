package oidc

import (
	"context"
	"errors"

	"github.com/onhotpath/tempogate/perms"
)

// PermissionResolver maps an admitted person to the Temporal permissions their
// access token carries. An empty grant means they get no token: tempogate
// denies by default. The authz package implements it from configuration and
// is bound via fx.As, so this package never imports it.
//
// The token endpoint is the authoritative caller (every grant mints through
// Token.issue); the Google callback and the device verification page consult
// it as well, so a person with no grant is told at sign-in instead of
// receiving a code or token that Temporal would refuse everywhere.
type PermissionResolver interface {
	Resolve(ctx context.Context, email string) (*perms.Grant, error)
}

// AuthzObserver is told every time an admitted person is refused because
// the PermissionResolver grants them nothing. stage is one of the authzStage*
// constants below, a fixed set usable as a metrics label.
type AuthzObserver interface {
	ObserveAuthzDenied(stage string)
}

const (
	// authzStageLogin is the Google callback, before any code is minted.
	authzStageLogin = "login"
	// authzStageDeviceVerification is the device verification page, before a
	// device code is approved.
	authzStageDeviceVerification = "device_verification"
	// The /token grants use their grant labels (grantLabel*) as stages.
)

// msgNoAccess is the error_description and page text for a person no rule
// grants anything to. It names no identity: it ends up in redirect URLs.
const msgNoAccess = "no Temporal access is granted to this account; ask an administrator for access"

// errNoPermissions is what Token.issue returns when the PermissionResolver grants
// nothing; each grant turns it into its own OAuth2 error.
var errNoPermissions = errors.New("oidc: no Temporal permissions are granted to this account")

// denyAll is the PermissionResolver of a component built without one: fail closed.
type denyAll struct{}

func (denyAll) Resolve(context.Context, string) (*perms.Grant, error) { return perms.New(), nil }

// permitted resolves email and reports whether it is granted anything. A
// resolver error is returned as is: the caller fails the request closed.
func permitted(ctx context.Context, a PermissionResolver, email string) (*perms.Grant, bool, error) {
	g, err := a.Resolve(ctx, email)
	if err != nil {
		return nil, false, err
	}
	return g, g != nil && !g.Empty(), nil
}
