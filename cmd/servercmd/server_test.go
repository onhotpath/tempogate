package servercmd

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	"github.com/onhotpath/tempogate/api"
	"github.com/onhotpath/tempogate/config"
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
		onListening: func(net.Addr) { called = true },
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
		server:          srv,
		shutdownTimeout: time.Second,
		onListening:     func(net.Addr) { close(listening) },
		onStopping:      func() { stopped = true },
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

var hardened = config.ServerConfig{
	ReadHeaderTimeout: 1 * time.Second,
	ReadTimeout:       2 * time.Second,
	WriteTimeout:      3 * time.Second,
	IdleTimeout:       4 * time.Second,
	MaxHeaderBytes:    8 << 10,
	ShutdownTimeout:   5 * time.Second,
}

// Both listeners must carry identical hardening: the admin surface is private
// but still reachable by anything inside the cluster network.
func (s *HTTPServerSuite) TestPublicAndAdminShareHardening() {
	ok := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	p := serveParams{
		Servers: &api.Servers{
			Public: &api.Surface{Handler: ok},
			Admin:  &api.Surface{Handler: ok},
		},
		Listener:      config.Listener{IP: net.IPv4(127, 0, 0, 1), Port: 8000},
		AdminListener: config.Listener{IP: net.IPv4(127, 0, 0, 1), Port: 8081},
		Server:        hardened,
	}

	public, admin := httpServers(p)

	s.Equal("127.0.0.1:8000", public.Addr)
	s.Equal("127.0.0.1:8081", admin.Addr)
	for name, srv := range map[string]*http.Server{"public": public, "admin": admin} {
		s.Run(name, func() {
			s.NotNil(srv.Handler)
			s.Equal(hardened.ReadHeaderTimeout, srv.ReadHeaderTimeout)
			s.Equal(hardened.ReadTimeout, srv.ReadTimeout)
			s.Equal(hardened.WriteTimeout, srv.WriteTimeout)
			s.Equal(hardened.IdleTimeout, srv.IdleTimeout)
			s.Equal(hardened.MaxHeaderBytes, srv.MaxHeaderBytes)
		})
	}
}

func (s *HTTPServerSuite) TestRejectsOversizedHeaders() {
	addr, _ := s.serve(newHTTPServer("127.0.0.1:0", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), hardened), time.Second)

	s.Equal(http.StatusOK, s.statusWithHeader(addr, 1<<10))
	// net/http allows 4 KiB of slack over MaxHeaderBytes, so go well past it.
	s.Equal(http.StatusRequestHeaderFieldsTooLarge, s.statusWithHeader(addr, 64<<10))
}

// An in-flight request that outlives the grace period must not block the
// component from returning: shutdown is bounded and then force-closes.
func (s *HTTPServerSuite) TestShutdownIsBounded() {
	entered := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	blocking := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		close(entered)
		<-release
	})
	addr, stop := s.serve(newHTTPServer("127.0.0.1:0", blocking, hardened), 200*time.Millisecond)

	clientErr := make(chan error, 1)
	go func() {
		resp, err := http.Get("http://" + addr)
		if err == nil {
			_ = resp.Body.Close()
		}
		clientErr <- err
	}()
	<-entered

	start := time.Now()
	err := stop()
	s.Less(time.Since(start), 2*time.Second, "shutdown must honour the grace period")
	s.ErrorIs(err, context.DeadlineExceeded)

	select {
	case err := <-clientErr:
		s.Error(err, "in-flight connection must be closed once the grace period expires")
	case <-time.After(2 * time.Second):
		s.Fail("in-flight connection still open after forced shutdown")
	}
}

// serve runs the httpServer component and returns the bound address plus a
// stop func that cancels the component and waits for it to return.
func (s *HTTPServerSuite) serve(srv *http.Server, grace time.Duration) (string, func() error) {
	ctx, cancel := context.WithCancel(context.Background())
	bound := make(chan net.Addr, 1)
	done := make(chan error, 1)
	go func() {
		done <- httpServer(httpServerOptions{
			server:          srv,
			shutdownTimeout: grace,
			onListening:     func(addr net.Addr) { bound <- addr },
		})(ctx)
	}()

	var addr net.Addr
	select {
	case addr = <-bound:
	case err := <-done:
		s.FailNow("server exited before listening", "%v", err)
	}

	stopped := false
	stop := func() error {
		stopped = true
		cancel()
		select {
		case err := <-done:
			return err
		case <-time.After(10 * time.Second):
			s.FailNow("server component did not return")
			return nil
		}
	}
	s.T().Cleanup(func() {
		if !stopped {
			_ = stop()
		}
	})
	return addr.String(), stop
}

func (s *HTTPServerSuite) statusWithHeader(addr string, size int) int {
	conn, err := net.Dial("tcp", addr)
	s.Require().NoError(err)
	defer func() { _ = conn.Close() }()

	_, err = fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: x\r\nX-Pad: %s\r\nConnection: close\r\n\r\n", strings.Repeat("a", size))
	s.Require().NoError(err)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	s.Require().NoError(err)
	_ = resp.Body.Close()
	return resp.StatusCode
}
