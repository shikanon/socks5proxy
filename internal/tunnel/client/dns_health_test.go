package client

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/shikanon/socks5proxy/internal/tunnel/protocol"
	"github.com/shikanon/socks5proxy/internal/tunnel/testutil"
	"github.com/shikanon/socks5proxy/internal/tunnel/transport"
	"golang.org/x/net/dns/dnsmessage"
)

func healthResponse() protocol.Message {
	return protocol.Message{ClientIPv4: "10.0.0.2", DNSIPv4: "1.1.1.1", MTU: 1150, Heartbeat: true}
}

func dnsReply(t *testing.T, request []byte, mutate func(*dnsmessage.Message)) []byte {
	t.Helper()
	info, err := protocol.ValidatePacket(request, 0)
	udp, ok := packetUDP(request)
	if err != nil || !ok {
		t.Fatalf("bad probe packet: %v", err)
	}
	var msg dnsmessage.Message
	if err := msg.Unpack(udp[8:]); err != nil {
		t.Fatal(err)
	}
	msg.Response, msg.RecursionAvailable = true, true
	q := msg.Questions[0]
	answer := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: q.Type, Class: q.Class, TTL: 60},
		Body: &dnsmessage.AResource{A: [4]byte{93, 184, 216, 34}}}
	if q.Type == dnsmessage.TypeAAAA {
		answer.Body = &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2001:db8::2").As16()}
	}
	msg.Answers = []dnsmessage.Resource{answer}
	if mutate != nil {
		mutate(&msg)
	}
	body, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return udpPacket(info.Destination, info.Source, 53, binary.BigEndian.Uint16(udp[:2]), body)
}

func TestDNSHealthChecksumsAndExactReplies(t *testing.T) {
	r := healthResponse()
	r.ClientIPv6, r.DNSIPv6, r.MTU = "fd00:5:5::2", "2606:4700:4700::1111", 1280
	for _, family := range []int{0, 1} {
		for _, scenario := range []string{"valid", "id", "question", "source", "port", "checksum", "servfail", "empty", "unrelated_answer", "truncated", "stale"} {
			t.Run([]string{"ipv4", "ipv6"}[family]+"/"+scenario, func(t *testing.T) {
				paths, err := newDNSPaths(r, "Example.com.")
				if err != nil {
					t.Fatal(err)
				}
				p := &paths[family]
				now := time.Now()
				request := p.request(now, time.Second)
				udp, ok := packetUDP(request)
				if !ok || checksum(udpPseudo(request, udp)) != 0 {
					t.Fatal("invalid generated UDP checksum")
				}
				mutate := func(msg *dnsmessage.Message) {
					switch scenario {
					case "id":
						msg.ID++
					case "question":
						msg.Questions[0].Name = dnsmessage.MustNewName("different.example.")
					case "servfail":
						msg.RCode = dnsmessage.RCodeServerFailure
					case "empty":
						msg.Answers = nil
					case "unrelated_answer":
						msg.Answers[0].Header.Name = dnsmessage.MustNewName("different.example.")
					case "truncated":
						msg.Truncated = true
					}
				}
				reply := dnsReply(t, request, mutate)
				info, _ := protocol.ValidatePacket(reply, 0)
				body, _ := packetUDP(reply)
				switch scenario {
				case "source":
					src := netip.MustParseAddr("1.0.0.1")
					if family == 1 {
						src = netip.MustParseAddr("2606:4700:4700::1001")
					}
					reply = udpPacket(src, info.Destination, 53, binary.BigEndian.Uint16(body[2:4]), body[8:])
				case "port":
					reply = udpPacket(info.Source, info.Destination, 53, binary.BigEndian.Uint16(body[2:4])+1, body[8:])
				case "checksum":
					reply[len(reply)-1] ^= 1
				case "stale":
					now = now.Add(time.Second)
				}
				consumed := p.reply(reply, now, time.Second)
				wantConsumed := scenario == "valid" || scenario == "servfail" || scenario == "empty" || scenario == "truncated" || scenario == "unrelated_answer"
				if consumed != wantConsumed || p.verified != (scenario == "valid") {
					t.Fatalf("consumed=%v healthy=%v", consumed, p.verified)
				}
				if scenario == "valid" && p.reply(reply, now, time.Second) {
					t.Fatal("replayed response consumed")
				}
			})
		}
	}
}

func TestLiveHeartbeatCannotHideForwardingFailure(t *testing.T) {
	for _, scenario := range []string{"silent_data", "ipv6_only_failure", "legacy_healthy", "healthy"} {
		t.Run(scenario, func(t *testing.T) {
			r := healthResponse()
			if scenario == "ipv6_only_failure" {
				r.ClientIPv6, r.DNSIPv6, r.MTU = "fd00:5:5::2", "2606:4700:4700::1111", 1280
			}
			if scenario == "legacy_healthy" {
				r.Heartbeat = false
			}
			for _, beforeRoutes := range []bool{true, false} {
				ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
				cc, closeConn := context.WithCancel(context.Background())
				conn := &relayConn{ctx: cc, cancel: closeConn, incoming: make(chan []byte, 64), sent: make(chan []byte, 64)}
				peerDone := make(chan struct{})
				go func() {
					defer close(peerDone)
					for {
						select {
						case payload := <-conn.sent:
							if _, nonce, ok := protocol.ParseHeartbeat(payload); ok {
								conn.incoming <- protocol.Heartbeat(protocol.DatagramTypePong, nonce)
							} else if scenario != "silent_data" && !(scenario == "ipv6_only_failure" && payload[1] == protocol.DatagramTypeIPv6) {
								reply := dnsReply(t, payload[2:], nil)
								encoded, _, _ := protocol.EncodeDatagram(reply, r.MTU, nil)
								conn.incoming <- encoded
							}
						case <-cc.Done():
							return
						case <-ctx.Done():
							return
						}
					}
				}()
				start := time.Now()
				options := healthOptions{interval: 5 * time.Millisecond, timeout: 60 * time.Millisecond}
				var err error
				dev := &relayDevice{written: make(chan []byte, 64)}
				if beforeRoutes {
					err = probe(ctx, conn, r, nil, options)
				} else {
					err = relay(ctx, conn, dev, make(chan []byte), r, nil, &counters{}, options)
				}
				if scenario == "healthy" || scenario == "legacy_healthy" {
					if beforeRoutes && err != nil || !beforeRoutes && !errors.Is(err, context.DeadlineExceeded) {
						t.Fatalf("healthy path failed: %v", err)
					}
				} else if !errors.Is(err, errHealthTimeout) || time.Since(start) > 150*time.Millisecond {
					t.Fatalf("forwarding deadline missed: %v", err)
				}
				if len(dev.written) != 0 {
					t.Fatal("health response leaked into application TUN")
				}
				cancel()
				closeConn()
				<-peerDone
			}
		})
	}
}

func TestTCPProbeRetriesAndLeavesConnectionUsable(t *testing.T) {
	serverTLS, clientTLS := testutil.TLS(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	listener, err := transport.ListenTunnel("127.0.0.1:0", serverTLS, "tcp")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	peerDone := make(chan error, 1)
	go func() {
		c, err := listener.Accept(ctx)
		if err != nil {
			peerDone <- err
			return
		}
		defer c.CloseWithError(0, "done")
		stream, err := c.AcceptControl(ctx)
		if err == nil {
			err = stream.Close()
		}
		if err != nil {
			peerDone <- err
			return
		}
		dnsCount := 0
		for {
			payload, err := c.ReceiveDatagram(ctx)
			if err != nil {
				peerDone <- err
				return
			}
			if _, nonce, ok := protocol.ParseHeartbeat(payload); ok {
				err = c.SendDatagram(protocol.Heartbeat(protocol.DatagramTypePong, nonce))
				if nonce == 42 || err != nil {
					peerDone <- err
					return
				}
			} else {
				dnsCount++
				if dnsCount == 1 {
					continue // Force a retry while the original TCP receive is pending.
				}
				reply := dnsReply(t, payload[2:], nil)
				encoded, _, _ := protocol.EncodeDatagram(reply, 1150, nil)
				if err := c.SendDatagram(encoded); err != nil {
					peerDone <- err
					return
				}
			}
		}
	}()
	c, err := transport.DialTunnelWithControl(ctx, listener.Addr().String(), clientTLS, "tcp", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseWithError(0, "done")
	stream, err := c.OpenControl(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	if err := probe(ctx, c, healthResponse(), nil, healthOptions{interval: 10 * time.Millisecond, timeout: time.Second}); err != nil {
		t.Fatal("TCP retry failed:", err)
	}
	if err := c.SendDatagram(protocol.Heartbeat(protocol.DatagramTypePing, 42)); err != nil {
		t.Fatal("probe closed healthy TCP connection:", err)
	}
	for {
		payload, err := c.ReceiveDatagram(ctx)
		if err != nil {
			t.Fatal("probe left TCP receive unusable:", err)
		}
		if kind, nonce, ok := protocol.ParseHeartbeat(payload); ok && kind == protocol.DatagramTypePong && nonce == 42 {
			break
		}
	}
	if err := <-peerDone; err != nil {
		t.Fatal(err)
	}
}
