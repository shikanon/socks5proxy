package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/shikanon/socks5proxy/internal/tunnel"
	"github.com/shikanon/socks5proxy/internal/tunnel/protocol"
	"github.com/shikanon/socks5proxy/internal/tunnel/testutil"
	"github.com/shikanon/socks5proxy/internal/tunnel/transport"
)

func TestConnectTCPAuthentication(t *testing.T) {
	serverTLS, clientTLS := testutil.TLS(t)
	token := strings.Repeat("a", 32)
	key := sha256.Sum256([]byte(token))
	for _, kind := range []string{"tcp", "tcp-plain"} {
		for _, scenario := range []string{"valid", "bad_challenge", "wrong_proof", "changed_mtu", "wrong_obfs", "rejected", "stalled"} {
			t.Run(kind+"/"+scenario, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				l, err := transport.ListenTunnel("127.0.0.1:0", serverTLS, kind)
				if err != nil {
					t.Fatal(err)
				}
				defer l.Close()
				done := make(chan error, 1)
				readRequest := make(chan struct{})
				go func() {
					c, err := l.Accept(ctx)
					if err != nil {
						done <- err
						return
					}
					defer c.CloseWithError(0, "test")
					s, err := c.AcceptControl(ctx)
					if err != nil {
						done <- err
						return
					}
					challenge, _ := protocol.NewNonce()
					if scenario == "bad_challenge" {
						challenge = "invalid"
					}
					err = protocol.WriteMessage(s, protocol.Message{Type: protocol.TypeAuthChallenge, Version: protocol.Version, Nonce: challenge})
					if scenario == "bad_challenge" {
						done <- err
						return
					}
					request, err := protocol.ReadMessage(s)
					if err != nil || request.Token != "" || !protocol.VerifyAuthProof(key, protocol.ClientProofRole, challenge, request.Nonce, request) {
						done <- errors.New("invalid client challenge proof")
						return
					}
					close(readRequest)
					if scenario == "stalled" {
						<-ctx.Done()
						done <- nil
						return
					}
					response := protocol.Message{Type: protocol.TypeAuthResponse, Version: protocol.Version, ClientIPv4: "10.0.0.2", ServerIPv4: "10.0.0.1", DNSIPv4: "1.1.1.1", MTU: 1150, Obfs: "random"}
					response.Proof = protocol.AuthProof(key, protocol.ServerProofRole, challenge, request.Nonce, response)
					switch scenario {
					case "wrong_proof":
						response.Proof = strings.Repeat("0", 64)
					case "changed_mtu":
						response.MTU++
					case "wrong_obfs":
						response.Obfs = "none"
					case "rejected":
						response = protocol.Message{Type: protocol.TypeError, Version: protocol.Version, Error: "authentication failed"}
					}
					if err := protocol.WriteMessage(s, response); err != nil {
						done <- err
						return
					}
					if scenario != "valid" {
						done <- nil
						return
					}
					if err := s.Close(); err != nil {
						done <- err
						return
					}
					payload, err := c.ReceiveDatagram(ctx)
					if err == nil {
						cipher, _ := tunnel.NewObfuscator("random", hex.EncodeToString(key[:]))
						decoded, _, decodeErr := protocol.DecodeDatagram(payload, 1150, cipher)
						if decodeErr != nil || len(decoded) != 20 {
							err = errors.New("client used incorrect TCP obfuscation key")
						}
					}
					done <- err
				}()
				if scenario == "stalled" {
					go func() {
						select {
						case <-readRequest:
							cancel()
						case <-ctx.Done():
						}
					}()
				}
				c, _, cipher, err := connect(ctx, l.Addr().String(), "desktop", token, "random", clientTLS, kind)
				if scenario == "valid" {
					if err != nil {
						t.Fatal(err)
					}
					defer c.CloseWithError(0, "test")
					packet := make([]byte, 20)
					packet[0], packet[3] = 0x45, 20
					copy(packet[12:], []byte{10, 0, 0, 2})
					payload, _, err := protocol.EncodeDatagram(packet, 1150, cipher)
					if err != nil {
						t.Fatal(err)
					}
					if bytes.Contains(payload, packet) {
						t.Fatal("random obfuscation did not encode packet")
					}
					if err := c.SendDatagram(payload); err != nil {
						t.Fatal(err)
					}
				} else if err == nil || c != nil {
					t.Fatal("invalid or canceled authentication succeeded")
				}
				if err := <-done; err != nil {
					t.Fatal("peer failed:", err)
				}
			})
		}
	}
}
