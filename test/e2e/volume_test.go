//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
)

// stateVolume returns a unique named-volume name for the migrate/serve
// containers to share, and removes the volume when the test ends. Docker
// creates it on first mount and neither Terminate nor the reaper removes a
// named volume, so without this every run leaks one. Call it before the
// containers are tracked: t.Cleanup is LIFO, so the removal then runs after
// every container using the volume has been terminated.
func stateVolume(t *testing.T, prefix string) string {
	t.Helper()
	name := fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
	t.Cleanup(func() {
		opts := testcontainers.NewTerminateOptions(context.Background(), testcontainers.RemoveVolumes(name))
		if err := opts.Cleanup(); err != nil {
			t.Logf("e2e: remove state volume %s: %v", name, err)
		}
	})
	return name
}
