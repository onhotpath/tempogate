//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package cli

import (
	"errors"
	"os"
	"syscall"
)

// tryLock takes an exclusive flock on f without blocking, so the caller can
// poll against its own deadline and context. flock is held per open file
// description, so it excludes other goroutines with their own open as well as
// other processes, and the kernel drops it if the holder dies.
func tryLock(f *os.File) (bool, error) {
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) // #nosec G115 -- a file descriptor always fits in an int
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return false, nil
	}
	return err == nil, err
}
