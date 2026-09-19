package client

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/shikanon/socks5proxy/internal/tunnel/protocol"
	"github.com/shikanon/socks5proxy/internal/tunnel/testutil"
	"github.com/shikanon/socks5proxy/internal/tunnel/transport"
)

func TestConnectCancelsStalledAuthentication(t *testing.T) {
	serverTLS, clientTLS := testutil.TLS(t)
	listener, err := transport.Listen("127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	peerCtx, stopPeer := context.WithTimeout(context.Background(), 3*time.Second)
	defer stopPeer()
	requestRead := make(chan error, 1)
	go func() {
		conn, err := listener.Accept(peerCtx)
		if err != nil {
			requestRead <- err
			return
		}
		defer conn.CloseWithError(0, "test done")
		stream, err := conn.AcceptStream(peerCtx)
		if err == nil {
			_, err = protocol.ReadMessage(stream)
		}
		requestRead <- err
		<-peerCtx.Done()
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		conn, _, _, err := connect(ctx, listener.Addr().String(), "client", strings.Repeat("a", 32), "none", clientTLS, "quic")
		if conn != nil {
			_ = conn.CloseWithError(0, "test done")
		}
		done <- err
	}()
	if err := <-requestRead; err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("stalled authentication succeeded")
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("authentication read ignored context cancellation")
	}
}
