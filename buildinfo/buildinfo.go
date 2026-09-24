// Package buildinfo exposes ldflag-injected build metadata.
//
// Values are populated at link time via -X github.com/onhotpath/tempogate/buildinfo.<var>.
// When unset (e.g. `go run`), accessors return "dev" / "unknown" sentinels.
package buildinfo

const (
	devVersion = "dev"
	unknown    = "unknown"
)

var (
	version   = devVersion
	gitTag    = unknown
	gitCommit = unknown
	buildDate = unknown
)

func Version() string  { return version }
func Tag() string      { return gitTag }
func Commit() string   { return gitCommit }
func DateTime() string { return buildDate }
