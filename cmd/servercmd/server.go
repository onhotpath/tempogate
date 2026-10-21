package servercmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/gojekfarm/xrun"
)

type httpServerOptions struct {
	server *http.Server

	// shutdownTimeout bounds graceful shutdown; connections still active
	// when it expires are force-closed.
	shutdownTimeout time.Duration

	// onListening fires after net.Listen succeeds and before Serve starts
	// accepting. Use this to flip /readyz, expose the bound port, etc.
	onListening func(addr net.Addr)

	// onStopping fires when ctx is cancelled, before srv.Shutdown is called.
	onStopping func()
}

// httpServer returns an xrun.ComponentFunc that binds the listener up-front
// (so onListening fires only once the OS confirms we're holding the port,
// preserving accurate /readyz semantics), serves until ctx cancels, then
// gracefully Shuts down within shutdownTimeout.
//
// Compared to xrun/component.HTTPServer this trades the convenience of
// ListenAndServe for the ability to observe a successful bind separately
// from the goroutine that runs Serve.
func httpServer(opts httpServerOptions) xrun.ComponentFunc {
	return func(ctx context.Context) error {
		lis, err := net.Listen("tcp", opts.server.Addr)
		if err != nil {
			return err
		}
		if opts.onListening != nil {
			opts.onListening(lis.Addr())
		}

		errCh := make(chan error, 1)
		go func() {
			if err := opts.server.Serve(lis); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- err
			}
		}()

		select {
		case <-ctx.Done():
		case err := <-errCh:
			return err
		}

		if opts.onStopping != nil {
			opts.onStopping()
		}
		// Not derived from ctx: it is already cancelled, and Shutdown needs a
		// live deadline to drain in-flight requests.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), opts.shutdownTimeout)
		defer cancel()
		if err := opts.server.Shutdown(shutdownCtx); err != nil {
			// Shutdown leaves active connections open on timeout; drop them so
			// a stuck client cannot hold the process past its grace.
			_ = opts.server.Close()
			return fmt.Errorf("graceful shutdown: %w", err)
		}
		return nil
	}
}
