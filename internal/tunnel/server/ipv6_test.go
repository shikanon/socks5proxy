package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shikanon/socks5proxy/internal/keytable"
	"github.com/shikanon/socks5proxy/internal/tunnel"
	"github.com/shikanon/socks5proxy/internal/tunnel/protocol"
	clientsession "github.com/shikanon/socks5proxy/internal/tunnel/session"
	"github.com/shikanon/socks5proxy/internal/tunnel/testutil"
	"github.com/shikanon/socks5proxy/internal/tunnel/transport"
)

type duplexDevice struct {
	memoryDevice
	reads chan []byte
	ctx   context.Context
}

func (d *duplexDevice) ReadPacket() ([]byte, error) {
	select {
	case p := <-d.reads:
		return p, nil
	case <-d.ctx.Done():
		return nil, d.ctx.Err()
	}
}

func serverIPv6Packet(src, dst string, size int) []byte {
	p := make([]byte, size)
	p[0], p[6], p[7] = 0x60, 17, 64
	binary.BigEndian.PutUint16(p[4:6], uint16(size-40))
	a, b := netip.MustParseAddr(src).As16(), netip.MustParseAddr(dst).As16()
	copy(p[8:24], a[:])
	copy(p[24:40], b[:])
	return p
}

func TestDualStackAuthenticatedSessions(t *testing.T) {
	serverTLS, clientTLS := testutil.TLS(t)
	for _, kind := range []string{"quic", "tcp", "tcp-table"} {
		for _, mode := range []string{"dual", "legacy", "unsupported"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				l, err := transport.ListenTunnel("127.0.0.1:0", serverTLS, kind)
				if err != nil {
					t.Fatal(err)
				}
				defer l.Close()
				table, _, err := keytable.LoadOrCreate(filepath.Join(t.TempDir(), "table"), 8)
				if err != nil {
					t.Fatal(err)
				}
				token := strings.Repeat("a", 32)
				if kind == "tcp-table" {
					token = table.Credential()
				}
				pool, _ := NewAddressPool("10.0.0.0/24")
				_ = pool.Reserve([]string{"desktop"})
				d := &duplexDevice{memoryDevice: memoryDevice{packets: make(chan []byte, 4)}, reads: make(chan []byte, 4), ctx: ctx}
				s := &Server{
					config: tunnel.ServerConfig{Transport: kind, IPv6: mode != "unsupported", TunnelCIDR6: "fd00:5:5::/64", DNSIPv6: "2001:db8::53", DNS: "1.1.1.1", MTU: 1400, ObfsAllow: map[string]bool{"none": true}},
					pool:   pool, device: d, sessions: newSessionTable(), table: table,
					tokens: &TokenStore{hashes: map[string][sha256.Size]byte{"desktop": sha256.Sum256([]byte(token))}},
				}
				done := make(chan struct{})
				go func() {
					defer close(done)
					c, err := l.Accept(ctx)
					if err == nil {
						s.handleConnection(ctx, c)
					}
				}()
				opt := clientsession.Options{IPv6: mode != "legacy"}
				var c transport.Conn
				var response protocol.Message
				var cipher protocol.Cipher
				if kind == "tcp-table" {
					c, response, cipher, err = clientsession.ConnectTable(ctx, l.Addr().String(), "desktop", table, nil, opt)
				} else {
					c, response, cipher, err = clientsession.Connect(ctx, l.Addr().String(), "desktop", token, "none", clientTLS, kind, nil, opt)
				}
				if mode == "unsupported" {
					if err == nil || c != nil {
						t.Fatal("unsupported IPv6 accepted")
					}
					<-done
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				defer c.CloseWithError(0, "test")
				if mode == "legacy" {
					if response.IPv6 || response.ClientIPv6 != "" || (kind == "quic" && response.MTU != tunnel.DefaultMTU) {
						t.Fatal("legacy compatibility broken", response)
					}
					return
				}
				downDone := make(chan struct{})
				go func() { s.downlink(ctx); close(downDone) }()
				defer func() { cancel(); <-downDone }()
				for _, size := range []int{1280, 1400} {
					spoof := serverIPv6Packet("fd00:5:5::ffff", "2001:db8::1", size)
					p, _, _ := protocol.EncodeDatagram(spoof, 1400, cipher)
					if err := c.SendDatagram(p); err != nil {
						t.Fatal(err)
					}
					packet := serverIPv6Packet(response.ClientIPv6, "2001:db8::1", size)
					p, _, _ = protocol.EncodeDatagram(packet, 1400, cipher)
					if err := c.SendDatagram(p); err != nil {
						t.Fatal(err)
					}
					select {
					case got := <-d.packets:
						if !bytes.Equal(got, packet) {
							t.Fatal("forged source reached TUN or uplink corrupted")
						}
					case <-ctx.Done():
						t.Fatal("IPv6 uplink did not reach TUN")
					}
					reply := serverIPv6Packet("2001:db8::1", response.ClientIPv6, size)
					d.reads <- reply
					got, err := c.ReceiveDatagram(ctx)
					decoded, _, decodeErr := protocol.DecodeDatagram(got, 1400, cipher)
					if err != nil || decodeErr != nil || !bytes.Equal(decoded, reply) {
						t.Fatal("IPv6 downlink failed", err, decodeErr)
					}
				}
				current := s.sessions.byAddress(netip.MustParseAddr(response.ClientIPv6))
				if current == nil || current.dropped.Load() != 2 {
					t.Fatal("IPv6 source spoofing was not rejected")
				}
				_ = c.CloseWithError(0, "test")
				select {
				case <-done:
				case <-ctx.Done():
					t.Fatal("dual-stack handler failed to exit")
				}
			})
		}
	}
}
