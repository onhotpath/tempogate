// Package oidc is the OIDC provider surface tempogate exposes to downstream
// clients (Temporal Web UI, the CLI loopback server). It federates the
// authorization-code flow to an upstream identity provider through a
// Connector; Google is the one implementation.
package oidc

import (
	"context"
	"time"
)

// AuthRequest is a pending authorization-code request, persisted between the
// downstream client's /authorize call and the upstream's round-trip back to
// /callback/<connector>. InternalState is the opaque token tempogate sends
// upstream as its `state`; the callback looks the request up by it.
//
// ClientState is the downstream client's own `state` parameter, echoed back
// to it unchanged when the flow completes — distinct from InternalState,
// which never leaves the tempogate↔upstream leg.
type AuthRequest struct {
	InternalState string
	// ConnectorID is the connector the browser was sent to; the callback
	// refuses the state at any other connector's callback.
	ConnectorID         string
	ClientID            string
	RedirectURI         string
	Scope               string
	ClientState         string
	CodeChallenge       string
	CodeChallengeMethod string

	// Nonce is the OIDC `nonce` the downstream client sent at /authorize, if
	// any. It is carried through to the minted ID token's nonce claim
	// (OIDC Core §2); empty when the client did not request one.
	Nonce string

	CreatedAt time.Time
	ExpiresAt time.Time
}

// AuthRequestStore is the consumer-side state interface for this package (see
// state/doc.go). The concrete sqlite.Store satisfies it structurally; the
// type is exported only so the composition root can inject it via fx.As.
type AuthRequestStore interface {
	SaveAuthRequest(ctx context.Context, ar AuthRequest) error
}
