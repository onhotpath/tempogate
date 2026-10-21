//go:build !lean

package app

import (
	"go.uber.org/fx"

	"github.com/onhotpath/tempogate/cmd/servercmd"
)

// serverModules wires the server-bound subcommands (serve, migrate, keys,
// gen-oas). Each builds the part of the HTTP server stack it needs (SQLite
// state store, signing keys, OIDC issuer, Google upstream, the API surface)
// only when it runs, so the root graph and every other subcommand never pay
// for, or fail on, the server's configuration.
//
// It is excluded from the lean CLI build (-tags lean, see modules_lean.go):
// nothing in the lean binary imports these packages, so the Go linker drops
// the entire SQLite/libc/OIDC/API subtree (~4 MB) - smaller artifact, smaller
// attack surface, and no SQLite is opened just to run `login`/`token`.
func serverModules() []fx.Option {
	return []fx.Option{
		servercmd.Fx(),
	}
}
