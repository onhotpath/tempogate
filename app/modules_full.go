//go:build !lean

package app

import (
	"go.uber.org/fx"

	"github.com/onhotpath/tempogate/admin"
	"github.com/onhotpath/tempogate/api"
	"github.com/onhotpath/tempogate/cmd/servercmd"
	"github.com/onhotpath/tempogate/keys"
	"github.com/onhotpath/tempogate/oidc"
	"github.com/onhotpath/tempogate/oidc/google"
	"github.com/onhotpath/tempogate/state/sqlite"
)

// serverModules wires the HTTP server stack (SQLite state store, signing
// keys, OIDC issuer, Google upstream, the API surface) and the server-bound
// subcommands (serve, migrate, keys).
//
// It is excluded from the lean CLI build (-tags lean, see modules_lean.go):
// nothing in the lean binary imports these packages, so the Go linker drops
// the entire SQLite/libc/OIDC/API subtree (~4 MB) — smaller artifact, smaller
// attack surface, and no SQLite is opened just to run `login`/`token`.
func serverModules() []fx.Option {
	return []fx.Option{
		sqlite.Fx(),
		keys.Fx(),
		oidc.Fx(),
		admin.Fx(),
		google.Fx(),
		api.Fx(),
		servercmd.Fx(),
	}
}
