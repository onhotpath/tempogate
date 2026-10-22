package oidc

import (
	"crypto/hmac"
	"crypto/sha256"
)

// MAC labels domain-separate every HMAC computed under
// OIDC_SESSION_SIGNING_KEY. The session cookie and the device bounce state
// share that key and the same "payload.mac" wire shape, so without a label a
// value minted for one purpose would verify as the other.
const (
	macLabelSessionCookie     = "tempogate/session-cookie"
	macLabelDeviceBounceState = "tempogate/device/bounce-state"
)

// labeledMAC is HMAC-SHA256(key, label || 0x00 || msg). The NUL keeps a
// label from running into the message, so no (label, msg) pair can collide
// with another label's.
func labeledMAC(key []byte, label string, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(label))
	m.Write([]byte{0})
	m.Write(msg)
	return m.Sum(nil)
}
