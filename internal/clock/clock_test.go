package clock

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNowIsUTCMicroseconds(t *testing.T) {
	now := Now()
	require.Equal(t, time.UTC, now.Location())
	require.Zero(t, now.Nanosecond()%int(time.Microsecond))
	require.WithinDuration(t, time.Now(), now, time.Minute)
}
