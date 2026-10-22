package sqlite

import (
	"context"
	"time"

	"github.com/onhotpath/tempogate/admin"
	"github.com/onhotpath/tempogate/keys"
)

func changeKeypair(kid string, at time.Time) keys.Keypair {
	return keys.Keypair{Kid: kid, Alg: "RS256", PrivatePEM: []byte("priv"), PublicPEM: []byte("pub"), CreatedAt: at}
}

func (s *StoreSuite) receive(ch <-chan keys.Change) keys.Change {
	select {
	case c := <-ch:
		return c
	case <-time.After(5 * time.Second):
		s.FailNow("no change published")
		return keys.Change{}
	}
}

func (s *StoreSuite) requireQuiet(ch <-chan keys.Change) {
	select {
	case c := <-ch:
		s.FailNowf("unexpected change", "%+v", c)
	default:
	}
}

func (s *StoreSuite) TestChangesArePublishedForCommittedWritesOnly() {
	ch := s.store.SubscribeChanges(s.ctx)
	at := time.Now().UTC()

	s.Require().NoError(s.store.SaveKeypair(s.ctx, changeKeypair("a", at)))
	s.Equal(keys.Change{Kind: keys.ChangeKeys}, s.receive(ch))
	s.Require().Error(s.store.SaveKeypair(s.ctx, changeKeypair("a", at)))
	s.requireQuiet(ch)

	s.Require().NoError(s.store.SaveKeypair(s.ctx, changeKeypair("b", at)))
	s.receive(ch)
	_, err := s.store.RetireKeypair(s.ctx, "a", at)
	s.Require().NoError(err)
	s.Equal(keys.Change{Kind: keys.ChangeKeys}, s.receive(ch))
	_, err = s.store.RetireKeypair(s.ctx, "a", at)
	s.Require().NoError(err)
	s.requireQuiet(ch) // already retired: nothing changed

	s.Require().NoError(s.store.UpdateKeypairPrivatePEM(s.ctx, "b", []byte("sealed")))
	s.Equal(keys.Change{Kind: keys.ChangeKeys}, s.receive(ch))
	s.Require().Error(s.store.UpdateKeypairPrivatePEM(s.ctx, "nope", []byte("sealed")))
	s.requireQuiet(ch)

	k := s.seedKey(admin.WithNamespace("ns"), admin.WithRole(admin.RoleRead), admin.WithOwner("o"))
	_, err = s.store.MarkIntegrationKeyRevoked(s.ctx, k.ID, at)
	s.Require().NoError(err)
	s.Equal(keys.Change{Kind: keys.ChangeJTIRevoked, JTI: k.JTI}, s.receive(ch))
	_, err = s.store.MarkIntegrationKeyRevoked(s.ctx, "unknown", at)
	s.Require().Error(err)
	s.requireQuiet(ch)
}

func (s *StoreSuite) TestASlowSubscriberMissesChangesWithoutBlockingWrites() {
	ch := s.store.SubscribeChanges(s.ctx)
	at := time.Now().UTC()
	for i := range cap(ch) + 3 {
		s.Require().NoError(s.store.SaveKeypair(s.ctx, changeKeypair(string(rune('a'+i)), at)))
	}
	s.Len(ch, cap(ch), "changes past the buffer are dropped, never waited for")
}

func (s *StoreSuite) TestSubscriptionClosesWithItsContext() {
	ctx, cancel := context.WithCancel(s.ctx)
	ch := s.store.SubscribeChanges(ctx)
	cancel()
	s.Eventually(func() bool {
		select {
		case _, ok := <-ch:
			return !ok
		default:
			return false
		}
	}, 5*time.Second, 5*time.Millisecond)

	// Publishing after the subscriber left must neither block nor panic.
	s.Require().NoError(s.store.SaveKeypair(s.ctx, changeKeypair("late", time.Now().UTC())))
}
