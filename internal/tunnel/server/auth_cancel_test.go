package server

import (
	"context"
	"testing"
	"time"

	"github.com/shikanon/socks5proxy/internal/tunnel/testutil"
	"github.com/shikanon/socks5proxy/internal/tunnel/transport"
)

func TestHandleConnectionCancelsPartialAuthentication(t *testing.T) {
	serverTLS, clientTLS := testutil.TLS(t)
	listener, err := transport.ListenTunnel("127.0.0.1:0", serverTLS, "quic")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client, err := transport.DialTunnel(ctx, listener.Addr().String(), clientTLS, "quic")
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseWithError(0, "test done")
	conn, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "test done")
	stream, err := client.OpenControl(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write([]byte{0}); err != nil {
		t.Fatal(err)
	}
	s := &Server{sessions: newSessionTable()}
	parent, stop := context.WithCancel(context.Background())
	defer stop()
	done := make(chan struct{})
	go func() { s.handleConnection(parent, conn); close(done) }()
	// Let the peer accept the queued stream and wait for the rest of the
	// header; a partial request must stay pending until canceled.
	select {
	case <-done:
		t.Fatal("partial authentication unexpectedly completed")
	case <-time.After(50 * time.Millisecond):
	}
	stop()
	select {
	case <-done:
	case <-time.After(300 * time.Millisecond):
		t.Fatal("partial authentication ignored parent cancellation")
	}
	if len(s.sessions.byClient) != 0 {
		t.Fatal("partial request created a session")
	}
}
