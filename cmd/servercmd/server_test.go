package servercmd

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

type HTTPServerSuite struct {
	suite.Suite
}

func TestHTTPServerSuite(t *testing.T) {
	suite.Run(t, new(HTTPServerSuite))
}

func (s *HTTPServerSuite) TestBindFailureReturnsErrorWithoutHooks() {
	held, err := net.Listen("tcp", "127.0.0.1:0")
	s.Require().NoError(err)
	defer held.Close()

	called := false
	run := httpServer(httpServerOptions{
		server:      &http.Server{Addr: held.Addr().String(), ReadHeaderTimeout: time.Second},
		onListening: func() { called = true },
		onStopping:  func() { called = true },
	})

	s.Error(run(context.Background()))
	s.False(called, "no hook may fire when the port could not be bound")
}

func (s *HTTPServerSuite) TestServesUntilCancelledThenShutsDown() {
	ctx, cancel := context.WithCancel(context.Background())
	listening := make(chan struct{})
	stopped := false
	srv := &http.Server{
		Addr:              "127.0.0.1:0",
		ReadHeaderTimeout: time.Second,
		Handler:           http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
	}
	run := httpServer(httpServerOptions{
		server:      srv,
		onListening: func() { close(listening) },
		onStopping:  func() { stopped = true },
	})

	done := make(chan error, 1)
	go func() { done <- run(ctx) }()

	select {
	case <-listening:
	case <-time.After(5 * time.Second):
		s.FailNow("onListening never fired")
	}
	cancel()

	select {
	case err := <-done:
		s.NoError(err)
	case <-time.After(5 * time.Second):
		s.FailNow("httpServer did not return after ctx was cancelled")
	}
	s.True(stopped, "onStopping must fire before Shutdown")
}
