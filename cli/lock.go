package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"
)

const (
	// defaultRefreshLockTimeout bounds how long EnsureFresh waits for another
	// process's refresh. A refresh is one HTTP round-trip with a 30s client
	// timeout, so a holder past this is stuck rather than slow.
	defaultRefreshLockTimeout = 30 * time.Second

	lockPollInterval = 25 * time.Millisecond
)

// ErrRefreshLockTimeout is returned when another process held the token
// file's refresh lock for longer than the lock timeout.
var ErrRefreshLockTimeout = errors.New("cli: timed out waiting for the token refresh lock")

// lockTokenFile takes the exclusive refresh lock for the token file at path:
// a sibling "<path>.lock" file. The lock file is left in place on release;
// removing it would let a waiter lock an unlinked inode while a newcomer
// locks a fresh one.
func lockTokenFile(ctx context.Context, path string, timeout time.Duration) (unlock func(), err error) {
	lockPath := path + ".lock"
	f, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, tokenFilePerm) // #nosec G304 -- sibling of the user's own token file
	if err != nil {
		return nil, fmt.Errorf("cli: open token lock file: %w", err)
	}

	deadline := time.Now().Add(timeout)
	for {
		ok, err := tryLock(f)
		if err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("cli: lock %s: %w", lockPath, err)
		}
		if ok {
			return func() { _ = f.Close() }, nil // closing the descriptor releases the lock
		}
		if !time.Now().Before(deadline) {
			_ = f.Close()
			return nil, fmt.Errorf("%w %s after %s; another tempogate process is refreshing this token file",
				ErrRefreshLockTimeout, lockPath, timeout)
		}
		select {
		case <-ctx.Done():
			_ = f.Close()
			return nil, fmt.Errorf("cli: waiting for token refresh lock: %w", ctx.Err())
		case <-time.After(lockPollInterval):
		}
	}
}
