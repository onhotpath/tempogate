//go:build !(darwin || dragonfly || freebsd || linux || netbsd || openbsd)

package cli

import "os"

// tryLock always succeeds where flock is unavailable (tempogate ships for
// Linux and macOS only). Concurrent refreshes of one token file are then
// unsynchronized and can be treated as refresh-token reuse, which ends the
// session; docs/cli-loopback-login.md records the limitation.
func tryLock(*os.File) (bool, error) { return true, nil }
