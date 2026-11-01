package client

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/shikanon/socks5proxy/internal/tunnel/protocol"
)

func TestHealthDetectsSilenceWrongNonceAndBlockedWrite(t *testing.T) {
	for _, scenario := range []string{"silence", "wrong_nonce", "blocked_write", "healthy"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			cc, closeConn := context.WithCancel(context.Background())
			defer closeConn()
			conn := &relayConn{ctx: cc, cancel: closeConn, incoming: make(chan []byte, 32), sent: make(chan []byte, 32), blockSend: scenario == "blocked_write", sendDone: make(chan struct{})}
			stopPeer := make(chan struct{})
			if scenario == "healthy" || scenario == "wrong_nonce" {
				go func() {
					defer close(stopPeer)
					for {
						select {
						case p := <-conn.sent:
							_, n, ok := protocol.ParseHeartbeat(p)
							if !ok {
								reply := dnsReply(t, p[2:], nil)
								p, _, _ = protocol.EncodeDatagram(reply, 1150, nil)
								select {
								case conn.incoming <- p:
								case <-ctx.Done():
									return
								}
								continue
							}
							if scenario == "wrong_nonce" {
								n++
							}
							select {
							case conn.incoming <- protocol.Heartbeat(protocol.DatagramTypePong, n):
							case <-ctx.Done():
								return
							}
						case <-cc.Done():
							return
						case <-ctx.Done():
							return
						}
					}
				}()
			} else {
				close(stopPeer)
			}
			start := time.Now()
			err := relay(ctx, conn, &relayDevice{written: make(chan []byte, 4)}, make(chan []byte), healthResponse(), nil, &counters{}, healthOptions{interval: 5 * time.Millisecond, timeout: 40 * time.Millisecond})
			if scenario == "healthy" {
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("healthy peer timed out: %v", err)
				}
			} else if !errors.Is(err, errHealthTimeout) || time.Since(start) > 150*time.Millisecond {
				t.Fatalf("health deadline missed: %v", err)
			}
			cancel()
			<-stopPeer
			if scenario == "blocked_write" {
				select {
				case <-conn.sendDone:
				default:
					t.Fatal("writer did not join")
				}
			}
		})
	}
}

func TestProbeCancellationInterruptsBlockedWrite(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	cc, closeConn := context.WithCancel(context.Background())
	defer closeConn()
	conn := &relayConn{ctx: cc, cancel: closeConn, sent: make(chan []byte, 1), blockSend: true, sendDone: make(chan struct{})}
	if err := probe(ctx, conn, healthResponse(), nil, healthOptions{interval: 5 * time.Millisecond, timeout: time.Second}); err == nil {
		t.Fatal("blocked probe succeeded")
	}
	select {
	case <-conn.sendDone:
	default:
		t.Fatal("probe left blocked writer")
	}
}
