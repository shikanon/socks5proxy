package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/shikanon/socks5proxy/internal/tunnel"
	"github.com/shikanon/socks5proxy/internal/tunnel/protocol"
	"github.com/shikanon/socks5proxy/internal/tunnel/testutil"
	"github.com/shikanon/socks5proxy/internal/tunnel/transport"
)

type memoryDevice struct{ packets chan []byte }

func (d *memoryDevice) Name() string                { return "test" }
func (d *memoryDevice) MTU() int                    { return 1150 }
func (d *memoryDevice) Close() error                { return nil }
func (d *memoryDevice) ReadPacket() ([]byte, error) { return nil, errors.New("unused") }
func (d *memoryDevice) WritePacket(p []byte) error {
	d.packets <- append([]byte(nil), p...)
	return nil
}

func TestServerTransportSessions(t *testing.T) {
	serverTLS, clientTLS := testutil.TLS(t)
	token := strings.Repeat("a", 32)
	key := sha256.Sum256([]byte(token))
	for _, kind := range []string{"quic", "tcp", "tcp-plain"} {
		for _, obfs := range []string{"none", "simple", "random"} {
			t.Run(kind+"/"+obfs, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				l, err := transport.ListenTunnel("127.0.0.1:0", serverTLS, kind)
				if err != nil {
					t.Fatal(err)
				}
				defer l.Close()
				pool, _ := NewAddressPool("10.0.0.0/24")
				_ = pool.Reserve([]string{"desktop"})
				dev := &memoryDevice{packets: make(chan []byte, 4)}
				s := &Server{
					config: tunnel.ServerConfig{Transport: kind, MTU: 1150, DNS: "1.1.1.1", ObfsAllow: map[string]bool{obfs: true}},
					pool:   pool, tokens: &TokenStore{hashes: map[string][sha256.Size]byte{"desktop": key}},
					sessions: newSessionTable(), device: dev,
				}
				handlers := make(chan chan struct{}, 2)
				go func() {
					for n := 0; n < 2; n++ {
						c, err := l.Accept(ctx)
						if err != nil {
							return
						}
						done := make(chan struct{})
						handlers <- done
						go func() { s.handleConnection(ctx, c); close(done) }()
					}
				}()
				connectPeer := func() (transport.Conn, protocol.Message, protocol.Cipher) {
					c, err := transport.DialTunnel(ctx, l.Addr().String(), clientTLS, kind)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = c.CloseWithError(0, "test") })
					stream, err := c.OpenControl(ctx)
					if err != nil {
						t.Fatal(err)
					}
					request := protocol.Message{Type: protocol.TypeAuthRequest, Version: protocol.Version, ClientID: "desktop", Token: token, Obfs: obfs}
					challenge := ""
					obfsKey := token
					if kind != "quic" {
						msg, err := protocol.ReadMessage(stream)
						if err != nil || msg.Type != protocol.TypeAuthChallenge {
							t.Fatal("missing server challenge", err)
						}
						challenge = msg.Nonce
						request.Token = ""
						request.Nonce, _ = protocol.NewNonce()
						request.Proof = protocol.AuthProof(key, protocol.ClientProofRole, challenge, request.Nonce, request)
						obfsKey = hex.EncodeToString(key[:])
					}
					if err := protocol.WriteMessage(stream, request); err != nil {
						t.Fatal(err)
					}
					response, err := protocol.ReadMessage(stream)
					if err != nil || response.Type != protocol.TypeAuthResponse {
						t.Fatal("authentication failed", err, response.Type)
					}
					if kind != "quic" && !protocol.VerifyAuthProof(key, protocol.ServerProofRole, challenge, request.Nonce, response) {
						t.Fatal("server response proof invalid")
					}
					if err := stream.Close(); err != nil {
						t.Fatal(err)
					}
					cipher, _ := tunnel.NewObfuscator(obfs, obfsKey)
					return c, response, cipher
				}
				checkPacket := func(c transport.Conn, response protocol.Message, cipher protocol.Cipher) *session {
					packet := make([]byte, 20)
					packet[0], packet[3] = 0x45, 20
					source := netip.MustParseAddr(response.ClientIPv4).As4()
					copy(packet[12:16], source[:])
					copy(packet[16:20], []byte{8, 8, 8, 8})
					payload, _, _ := protocol.EncodeDatagram(packet, 1150, cipher)
					if err := c.SendDatagram(payload); err != nil {
						t.Fatal(err)
					}
					select {
					case got := <-dev.packets:
						if !bytes.Equal(got, packet) {
							t.Fatal("uplink changed packet")
						}
					case <-ctx.Done():
						t.Fatal("uplink did not reach TUN")
					}
					current := s.sessions.byAddress(netip.MustParseAddr(response.ClientIPv4))
					if current == nil {
						t.Fatal("authenticated session missing")
					}
					current.send <- payload
					got, err := c.ReceiveDatagram(ctx)
					if err != nil || !bytes.Equal(got, payload) {
						t.Fatal("downlink changed datagram", err)
					}
					return current
				}
				first, response, cipher := connectPeer()
				firstDone := <-handlers
				old := checkPacket(first, response, cipher)
				second, response2, cipher2 := connectPeer()
				secondDone := <-handlers
				current := checkPacket(second, response2, cipher2)
				if old == current || response.ClientIPv4 != response2.ClientIPv4 {
					t.Fatal("replacement did not retain client's reserved address")
				}
				select {
				case <-firstDone:
				case <-ctx.Done():
					t.Fatal("replaced handler did not exit")
				}
				if s.sessions.byAddress(current.addr) != current {
					t.Fatal("old handler removed replacement session")
				}
				s.sessions.closeAll()
				select {
				case <-secondDone:
				case <-ctx.Done():
					t.Fatal("session close did not end handler")
				}
				if s.sessions.byAddress(current.addr) != nil {
					t.Fatal("shutdown left registered session")
				}
			})
		}
	}
}
