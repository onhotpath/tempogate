package oidc

import (
	"context"
	"strings"

	"github.com/onhotpath/tempogate/redact"
)

// declareIdentity declares a person's email and upstream subject in the
// request's redact.Set, so neither leaves the process in what it exports.
// The email is declared lowercased too: authorization matches it that way.
func declareIdentity(ctx context.Context, subject, email string) {
	redact.Declare(ctx, redact.PII, email, strings.ToLower(email), subject)
}

// declareUserCode declares a device user code as typed, and in the
// canonical and display forms tempogate stores and shows.
func declareUserCode(ctx context.Context, raw string) {
	canonical := canonicalUserCode(raw)
	redact.Declare(ctx, redact.Secret, raw, canonical, formatUserCode(canonical))
}
