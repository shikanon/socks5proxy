package session

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/shikanon/socks5proxy/internal/tunnel/protocol"
	"github.com/shikanon/socks5proxy/internal/tunnel/testutil"
	"github.com/shikanon/socks5proxy/internal/tunnel/transport"
)

func TestLegacyTCPHeartbeatNegotiation(t *testing.T) {
	serverTLS, clientTLS := testutil.TLS(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	l, err := transport.ListenTunnel("127.0.0.1:0", serverTLS, "tcp")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	token := strings.Repeat("a", 32)
	key := sha256.Sum256([]byte(token))
	done := make(chan error, 1)
	go func() {
		for attempt := 0; attempt < 2; attempt++ {
			c, err := l.Accept(ctx)
			if err != nil {
				done <- err
				return
			}
			s, err := c.AcceptControl(ctx)
			if err != nil {
				c.CloseWithError(0, "test")
				done <- err
				return
			}
			challenge, _ := protocol.NewNonce()
			_ = protocol.WriteMessage(s, protocol.Message{Type: protocol.TypeAuthChallenge, Version: protocol.Version, Nonce: challenge})
			req, err := protocol.ReadMessage(s)
			if err != nil {
				c.CloseWithError(0, "test")
				done <- err
				return
			}
			requested := req.Heartbeat
			req.Heartbeat = false // What an old server sees after unmarshaling.
			valid := protocol.VerifyAuthProof(key, protocol.ClientProofRole, challenge, req.Nonce, req)
			if (attempt == 0 && (!requested || valid)) || (attempt == 1 && (requested || !valid)) {
				c.CloseWithError(0, "test")
				done <- errors.New("legacy proof request mismatch")
				return
			}
			if attempt == 0 {
				_ = protocol.WriteMessage(s, protocol.Message{Type: protocol.TypeError, Version: protocol.Version, Error: "authentication failed"})
				c.CloseWithError(0, "legacy rejection")
				continue
			}
			r := protocol.Message{Type: protocol.TypeAuthResponse, Version: protocol.Version, Obfs: "none", ClientIPv4: "10.0.0.2", ServerIPv4: "10.0.0.1", DNSIPv4: "1.1.1.1", MTU: 1150}
			r.Proof = protocol.AuthProof(key, protocol.ServerProofRole, challenge, req.Nonce, r)
			if err := protocol.WriteMessage(s, r); err != nil {
				c.CloseWithError(0, "test")
				done <- err
				return
			}
			_ = s.Close()
			_, _ = c.ReceiveDatagram(ctx)
			c.CloseWithError(0, "test")
		}
		done <- nil
	}()
	c, r, _, err := Connect(ctx, l.Addr().String(), "desktop", token, "none", clientTLS, "tcp", nil, Options{Heartbeat: true})
	if err != nil {
		t.Fatal(err)
	}
	if r.Heartbeat {
		t.Fatal("legacy server negotiated heartbeat")
	}
	c.CloseWithError(0, "test")
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
