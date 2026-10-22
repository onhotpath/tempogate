package changefeed

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/onhotpath/tempogate/keys"
)

func TestEverySubscriberReceivesAPublishedChange(t *testing.T) {
	var h Hub
	a, b := h.Subscribe(t.Context()), h.Subscribe(t.Context())
	c := keys.Change{Kind: keys.ChangeJTIRevoked, JTI: "j"}
	h.Publish(c)
	require.Equal(t, c, <-a)
	require.Equal(t, c, <-b)
}

func TestASlowSubscriberMissesChangesWithoutBlockingPublish(t *testing.T) {
	var h Hub
	ch := h.Subscribe(t.Context())
	for range buffer + 3 {
		h.Publish(keys.Change{Kind: keys.ChangeKeys})
	}
	require.Len(t, ch, buffer)
}

func TestSubscriptionClosesWithItsContext(t *testing.T) {
	var h Hub
	ctx, cancel := context.WithCancel(t.Context())
	ch := h.Subscribe(ctx)
	cancel()
	require.Eventually(t, func() bool {
		select {
		case _, ok := <-ch:
			return !ok
		default:
			return false
		}
	}, 5*time.Second, 5*time.Millisecond)
	h.Publish(keys.Change{Kind: keys.ChangeKeys}) // neither blocks nor panics
}
