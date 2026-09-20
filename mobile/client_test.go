package mobile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shikanon/socks5proxy/internal/tunnel"
	"github.com/shikanon/socks5proxy/internal/tunnel/protocol"
	"github.com/shikanon/socks5proxy/internal/tunnel/testutil"
	"github.com/shikanon/socks5proxy/internal/tunnel/transport"
)

type protector struct {
	allow bool
	calls atomic.Int32
}

func (p *protector) ProtectSocket(fd int) bool {
	p.calls.Add(1)
	return p.allow && fd >= 0
}

func newTestClient(t *testing.T) *Client {
	t.Helper()
	c, err := NewClient(configJSON(t, testConfig()), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestClientClose(t *testing.T) {
	t.Run("unblocks_reader_and_is_idempotent", func(t *testing.T) {
		c := newTestClient(t)
		done := make(chan error, 1)
		go func() { _, err := c.ReadPacket(); done <- err }()
		_ = c.Close()
		_ = c.Close()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("closed read succeeded")
			}
		case <-time.After(time.Second):
			t.Fatal("Close failed to unblock reader")
		}
		if _, err := c.Connect(); err == nil {
			t.Fatal("closed client connected")
		}
		if err := c.Start(); err == nil {
			t.Fatal("closed client started")
		}
		if err := c.WritePacket(ipPacket(2, 1)); err == nil {
			t.Fatal("closed client accepted packet")
		}
		if !strings.Contains(c.Status(), `"state":"closed"`) {
			t.Fatal(c.Status())
		}
	})
	t.Run("cancels_authentication", func(t *testing.T) {
		serverTLS, _ := testutil.TLS(t)
		l, err := transport.ListenTunnel("127.0.0.1:0", serverTLS, "tcp-plain")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		accepted := make(chan struct{})
		go func() {
			conn, err := l.Accept(ctx)
			if err != nil {
				return
			}
			defer conn.CloseWithError(0, "test")
			close(accepted)
			<-ctx.Done()
		}()
		cfg := testConfig()
		cfg.ServerAddr = l.Addr().String()
		c, _ := NewClient(configJSON(t, cfg), nil)
		defer c.Close()
		done := make(chan error, 1)
		go func() { _, err := c.Connect(); done <- err }()
		<-accepted
		_ = c.Close()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("canceled authentication succeeded")
			}
		case <-time.After(time.Second):
			t.Fatal("authentication ignored Close")
		}
	})
}

func TestClientWritePacket(t *testing.T) {
	c := newTestClient(t)
	p := ipPacket(2, 1)
	_ = c.WritePacket(p)
	p[12] = 99
	if got := <-c.outbound; got[12] == 99 {
		t.Fatal("packet buffer retained without copying")
	}
	for _, bad := range [][]byte{nil, {0x60}, make([]byte, 1401)} {
		_ = c.WritePacket(bad)
	}
	for i := 0; i < cap(c.outbound)+10; i++ {
		_ = c.WritePacket(ipPacket(2, 1))
	}
	if len(c.outbound) != cap(c.outbound) || c.dropped.Load() != 13 {
		t.Fatal("bounded queue or rejected packets mismatch", c.dropped.Load())
	}
}

func TestNewClient(t *testing.T) {
	if _, err := NewClient("{}", nil); err == nil {
		t.Fatal("missing config accepted")
	}
	cfg := testConfig()
	cfg.Transport, cfg.CAPEM = "quic", "invalid"
	if _, err := NewClient(configJSON(t, cfg), nil); err == nil {
		t.Fatal("bad CA accepted")
	}
}

func TestClientConnect(t *testing.T) {
	t.Run("protection_failure", func(t *testing.T) {
		for _, kind := range []string{"quic", "tcp", "tcp-plain"} {
			cfg := testConfig()
			cfg.Transport = kind
			p := &protector{}
			c, err := NewClient(configJSON(t, cfg), p)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = c.Connect(); err == nil || !strings.Contains(err.Error(), "protection failed") || p.calls.Load() != 1 {
				t.Fatal(kind, err, p.calls.Load())
			}
			_ = c.Close()
		}
	})
	t.Run("negotiated_parameter_rejected", func(t *testing.T) {
		l, clientTLS, ctx := testListener(t, "tcp-plain")
		go serveSession(ctx, l, "tcp-plain", "none", 1500, nil, nil)
		cfg := testConfig()
		cfg.ServerAddr = l.Addr().String()
		c, _ := NewClient(configJSON(t, cfg), nil)
		c.tls = clientTLS
		defer c.Close()
		if _, err := c.Connect(); err == nil || !strings.Contains(c.Status(), `"state":"error"`) {
			t.Fatal("oversized MTU accepted", err, c.Status())
		}
	})
}

func testListener(t *testing.T, kind string) (transport.Listener, *tls.Config, context.Context) {
	t.Helper()
	serverTLS, clientTLS := testutil.TLS(t)
	l, err := transport.ListenTunnel("127.0.0.1:0", serverTLS, kind)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	t.Cleanup(func() { cancel(); _ = l.Close() })
	return l, clientTLS, ctx
}

// The local peer implements the public auth protocol, then exposes packet mode.
func serveSession(ctx context.Context, l transport.Listener, kind, obfs string, mtu int, ready chan<- transport.Conn, done chan<- error) {
	report := func(err error) {
		if done != nil {
			done <- err
		}
	}
	c, err := l.Accept(ctx)
	if err != nil {
		report(err)
		return
	}
	defer c.CloseWithError(0, "test complete")
	s, err := c.AcceptControl(ctx)
	if err != nil {
		report(err)
		return
	}
	token := strings.Repeat("a", 32)
	key := sha256.Sum256([]byte(token))
	challenge := ""
	if kind != "quic" {
		challenge, _ = protocol.NewNonce()
		_ = protocol.WriteMessage(s, protocol.Message{Type: protocol.TypeAuthChallenge, Version: protocol.Version, Nonce: challenge})
	}
	request, err := protocol.ReadMessage(s)
	if err != nil {
		report(err)
		return
	}
	if kind == "quic" && request.Token != token || kind != "quic" && !protocol.VerifyAuthProof(key, protocol.ClientProofRole, challenge, request.Nonce, request) {
		report(errors.New("client authentication invalid"))
		return
	}
	response := protocol.Message{Type: protocol.TypeAuthResponse, Version: protocol.Version, ClientIPv4: "10.0.0.2", ServerIPv4: "10.0.0.1", DNSIPv4: "1.1.1.1", MTU: mtu, Obfs: obfs}
	if kind != "quic" {
		response.Proof = protocol.AuthProof(key, protocol.ServerProofRole, challenge, request.Nonce, response)
	}
	if err := protocol.WriteMessage(s, response); err != nil {
		report(err)
		return
	}
	_ = s.Close()
	if ready != nil {
		select {
		case ready <- c:
		case <-ctx.Done():
			return
		}
	}
	report(nil)
	select {
	case <-ctx.Done():
	case <-c.Context().Done():
	}
}

func ipPacket(source, destination byte) []byte {
	p := make([]byte, 20)
	p[0], p[3] = 0x45, 20
	copy(p[12:16], []byte{10, 0, 0, source})
	copy(p[16:20], []byte{10, 0, 0, destination})
	return p
}

func TestClientPacketRoundTrip(t *testing.T) {
	for _, kind := range []string{"quic", "tcp", "tcp-plain"} {
		for _, obfs := range []string{"none", "simple", "random"} {
			t.Run(kind+"/"+obfs, func(t *testing.T) {
				l, clientTLS, ctx := testListener(t, kind)
				ready := make(chan transport.Conn, 1)
				go serveSession(ctx, l, kind, obfs, 1150, ready, nil)
				cfg := testConfig()
				cfg.ServerAddr, cfg.Transport, cfg.Obfs = l.Addr().String(), kind, obfs
				p := &protector{allow: true}
				c, err := NewClient(configJSON(t, cfg), p)
				if err != nil {
					t.Fatal(err)
				}
				c.tls = clientTLS
				defer c.Close()
				if err := c.Start(); err == nil {
					t.Fatal("started without authentication")
				}
				raw, err := c.Connect()
				if err != nil {
					t.Fatal(err)
				}
				var parameters parameters
				if json.Unmarshal([]byte(raw), &parameters) != nil || parameters.ClientIPv4 != "10.0.0.2" {
					t.Fatal(raw)
				}
				if _, err := c.Connect(); err == nil {
					t.Fatal("duplicate Connect succeeded")
				}
				if err := c.Start(); err != nil {
					t.Fatal(err)
				}
				if err := c.Start(); err == nil {
					t.Fatal("duplicate Start succeeded")
				}
				peer := <-ready
				key := sha256.Sum256([]byte(cfg.Token))
				obfsKey := cfg.Token
				if kind != "quic" {
					obfsKey = hex.EncodeToString(key[:])
				}
				cipher, _ := tunnel.NewObfuscator(obfs, obfsKey)
				_ = c.WritePacket(ipPacket(99, 1)) // wrong source must be dropped
				_ = c.WritePacket(ipPacket(2, 1))
				payload, err := peer.ReceiveDatagram(ctx)
				if err != nil {
					t.Fatal(err)
				}
				packet, _, err := protocol.DecodeDatagram(payload, 1150, cipher)
				if err != nil || !bytes.Equal(packet, ipPacket(2, 1)) {
					t.Fatal("invalid outbound packet escaped", err)
				}
				bad, _, _ := protocol.EncodeDatagram(ipPacket(1, 99), 1150, cipher)
				good, _, _ := protocol.EncodeDatagram(ipPacket(1, 2), 1150, cipher)
				_ = peer.SendDatagram(bad)
				_ = peer.SendDatagram(good)
				got := make(chan []byte, 1)
				go func() { packet, _ := c.ReadPacket(); got <- packet }()
				select {
				case packet := <-got:
					if !bytes.Equal(packet, ipPacket(1, 2)) {
						t.Fatal("wrong destination escaped")
					}
				case <-ctx.Done():
					t.Fatal("no inbound packet")
				}
				if p.calls.Load() != 1 || c.sent.Load() != 20 || c.received.Load() != 20 || c.dropped.Load() != 2 {
					t.Fatal("protect/statistics mismatch", c.Status(), p.calls.Load())
				}
			})
		}
	}
}

func TestClientReconnect(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(map[bool]string{false: "same_lease", true: "changed_lease"}[changed], func(t *testing.T) {
			l, _, ctx := testListener(t, "tcp-plain")
			ready := make(chan transport.Conn, 2)
			go serveSession(ctx, l, "tcp-plain", "none", 1150, ready, nil)
			cfg := testConfig()
			cfg.ServerAddr = l.Addr().String()
			p := &protector{allow: true}
			c, _ := NewClient(configJSON(t, cfg), p)
			defer c.Close()
			if _, err := c.Connect(); err != nil {
				t.Fatal(err)
			}
			_ = c.Start()
			first := <-ready
			_ = first.CloseWithError(0, "force reconnect")
			mtu := 1150
			if changed {
				mtu--
			}
			go serveSession(ctx, l, "tcp-plain", "none", mtu, ready, nil)
			ticker := time.NewTicker(10 * time.Millisecond)
			defer ticker.Stop()
			for {
				status := c.Status()
				if changed && strings.Contains(status, `"state":"error"`) {
					if !strings.Contains(status, "changed tunnel parameters") {
						t.Fatal(status)
					}
					break
				}
				if !changed && p.calls.Load() == 2 && strings.Contains(status, `"state":"connected"`) {
					peer := <-ready
					_ = c.WritePacket(ipPacket(2, 1))
					if _, err := peer.ReceiveDatagram(ctx); err != nil {
						t.Fatal("reconnected transport unusable", err)
					}
					break
				}
				select {
				case <-ctx.Done():
					t.Fatal("reconnect did not settle", status)
				case <-ticker.C:
				}
			}
		})
	}
}
