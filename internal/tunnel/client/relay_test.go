package client

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/shikanon/socks5proxy/internal/tunnel/protocol"
	"github.com/shikanon/socks5proxy/internal/tunnel/transport"
)

type relayConn struct {
	ctx       context.Context
	cancel    context.CancelFunc
	incoming  chan []byte
	sent      chan []byte
	blockSend bool
	sendDone  chan struct{}
}

func (c *relayConn) Context() context.Context { return c.ctx }
func (c *relayConn) OpenControl(context.Context) (transport.ControlStream, error) {
	return nil, errors.New("unused")
}
func (c *relayConn) AcceptControl(context.Context) (transport.ControlStream, error) {
	return nil, errors.New("unused")
}
func (c *relayConn) CloseWithError(quic.ApplicationErrorCode, string) error {
	c.cancel()
	return nil
}
func (c *relayConn) SendDatagram(p []byte) error {
	c.sent <- p
	if c.blockSend {
		<-c.ctx.Done()
		close(c.sendDone)
		return c.ctx.Err()
	}
	return nil
}
func (c *relayConn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case p := <-c.incoming:
		return p, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.ctx.Done():
		return nil, c.ctx.Err()
	}
}

type relayDevice struct{ written chan []byte }

func (d *relayDevice) Name() string                { return "test" }
func (d *relayDevice) MTU() int                    { return 1150 }
func (d *relayDevice) Close() error                { return nil }
func (d *relayDevice) ReadPacket() ([]byte, error) { return nil, errors.New("unused") }
func (d *relayDevice) WritePacket(p []byte) error  { d.written <- p; return nil }

func TestRelayCancellationAndValidation(t *testing.T) {
	packet := func(source, destination byte) []byte {
		p := make([]byte, 20)
		p[0], p[3] = 0x45, 20
		copy(p[12:16], []byte{10, 0, 0, source})
		copy(p[16:20], []byte{10, 0, 0, destination})
		return p
	}
	for _, block := range []bool{false, true} {
		t.Run(map[bool]string{false: "address_validation", true: "joins_blocked_writer"}[block], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			connCtx, closeConn := context.WithCancel(context.Background())
			defer closeConn()
			conn := &relayConn{ctx: connCtx, cancel: closeConn, incoming: make(chan []byte, 4), sent: make(chan []byte, 4), blockSend: block, sendDone: make(chan struct{})}
			dev := &relayDevice{written: make(chan []byte, 4)}
			outbound := make(chan []byte, 4)
			outbound <- packet(3, 1)
			outbound <- packet(2, 1)
			for _, destination := range []byte{3, 2} {
				encoded, _, _ := protocol.EncodeDatagram(packet(1, destination), 1150, nil)
				conn.incoming <- encoded
			}
			stats := &counters{}
			done := make(chan error, 1)
			go func() {
				done <- relay(ctx, conn, dev, outbound, protocol.Message{ClientIPv4: "10.0.0.2", MTU: 1150}, nil, stats)
			}()
			select {
			case <-conn.sent:
			case <-time.After(time.Second):
				t.Fatal("valid outbound packet was not sent")
			}
			select {
			case got := <-dev.written:
				if got[19] != 2 {
					t.Fatal("wrong destination reached TUN")
				}
			case <-time.After(time.Second):
				t.Fatal("valid inbound packet did not reach TUN")
			}
			cancel()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("relay did not cancel blocked workers")
			}
			if conn.Context().Err() == nil || stats.dropped.Load() != 2 || stats.recv.Load() != 20 {
				t.Fatal("relay lifecycle or address validation failed")
			}
			if block {
				select {
				case <-conn.sendDone:
				default:
					t.Fatal("relay returned before writer stopped")
				}
			} else if stats.sent.Load() != 20 {
				t.Fatal("valid packet was not counted")
			}
		})
	}
}
