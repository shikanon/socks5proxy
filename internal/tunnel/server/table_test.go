package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/shikanon/socks5proxy/internal/keytable"
	"github.com/shikanon/socks5proxy/internal/tunnel"
	"github.com/shikanon/socks5proxy/internal/tunnel/protocol"
	clientsession "github.com/shikanon/socks5proxy/internal/tunnel/session"
	"github.com/shikanon/socks5proxy/internal/tunnel/transport"
)

func TestTableTunnelAuthenticationAndPackets(t *testing.T) {
	for _, scenario := range []string{"valid", "wrong_table", "wrong_client"} {
		t.Run(scenario, func(t *testing.T) {
			table, _, err := keytable.LoadOrCreate(filepath.Join(t.TempDir(), "table"), 8)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			listener, err := transport.ListenTunnel("127.0.0.1:0", nil, "tcp-table")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			pool, _ := NewAddressPool("10.0.0.0/24")
			_ = pool.Reserve([]string{"desktop"})
			dev := &memoryDevice{packets: make(chan []byte, 4)}
			server := &Server{
				config: tunnel.ServerConfig{Transport: "tcp-table", MTU: 1400, DNS: "1.1.1.1", ObfsAllow: map[string]bool{"none": true}},
				tokens: &TokenStore{hashes: map[string][sha256.Size]byte{"desktop": sha256.Sum256([]byte(table.Credential()))}},
				table:  table, pool: pool, device: dev, sessions: newSessionTable(),
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				conn, err := listener.Accept(ctx)
				if err == nil {
					server.handleConnection(ctx, conn)
				}
			}()
			clientTable, clientID := table, "desktop"
			if scenario == "wrong_table" {
				clientTable, _, err = keytable.LoadOrCreate(filepath.Join(t.TempDir(), "other"), 8)
				if err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "wrong_client" {
				clientID = "unknown"
			}
			conn, response, cipher, err := clientsession.ConnectTable(ctx, listener.Addr().String(), clientID, clientTable, nil)
			if scenario != "valid" {
				if err == nil || conn != nil {
					t.Fatal("invalid table credential accepted")
				}
				select {
				case <-done:
				case <-ctx.Done():
					t.Fatal("rejected session did not close")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer conn.CloseWithError(0, "test")
			for _, size := range []int{20, 1400} {
				packet := make([]byte, size)
				for i := range packet {
					packet[i] = byte(i)
				}
				packet[0], packet[2], packet[3] = 0x45, byte(size>>8), byte(size)
				clientIP := netip.MustParseAddr(response.ClientIPv4).As4()
				copy(packet[12:16], clientIP[:])
				copy(packet[16:20], []byte{8, 8, 8, 8})
				payload, _, err := protocol.EncodeDatagram(packet, 1400, cipher)
				if err != nil {
					t.Fatal(err)
				}
				if err := conn.SendDatagram(payload); err != nil {
					t.Fatal(err)
				}
				select {
				case got := <-dev.packets:
					if !bytes.Equal(got, packet) {
						t.Fatal("table uplink corrupted TUN packet")
					}
				case <-ctx.Done():
					t.Fatal("table uplink did not arrive")
				}
				current := server.sessions.byAddress(netip.MustParseAddr(response.ClientIPv4))
				if current == nil {
					t.Fatal("session was not registered")
				}
				current.send <- payload
				got, err := conn.ReceiveDatagram(ctx)
				if err != nil || !bytes.Equal(got, payload) {
					t.Fatal("table downlink corrupted packet", err)
				}
			}
			_ = conn.CloseWithError(0, "test")
			select {
			case <-done:
			case <-ctx.Done():
				t.Fatal("table session did not shut down")
			}
		})
	}
}
