package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
)

type ControlStream interface {
	io.ReadWriteCloser
	SetDeadline(time.Time) error
}

// Conn transports complete encoded IPv4 datagrams after control authentication.
type Conn interface {
	Context() context.Context
	OpenControl(context.Context) (ControlStream, error)
	AcceptControl(context.Context) (ControlStream, error)
	SendDatagram([]byte) error
	ReceiveDatagram(context.Context) ([]byte, error)
	CloseWithError(quic.ApplicationErrorCode, string) error
}

type Listener interface {
	Accept(context.Context) (Conn, error)
	Close() error
	Addr() net.Addr
}

type quicConn struct{ *quic.Conn }

// SocketControl runs before connecting or binding the outer tunnel socket.
// Android uses it to exclude every socket (including reconnects) from the VPN.
type SocketControl func(network, address string, socket syscall.RawConn) error

type ownedQUICConn struct {
	*quicConn
	socket net.PacketConn
}

func (c *ownedQUICConn) CloseWithError(code quic.ApplicationErrorCode, reason string) error {
	err := c.quicConn.CloseWithError(code, reason)
	_ = c.socket.Close()
	return err
}

func (c *quicConn) OpenControl(ctx context.Context) (ControlStream, error) {
	return c.OpenStreamSync(ctx)
}

func (c *quicConn) AcceptControl(ctx context.Context) (ControlStream, error) {
	support := c.ConnectionState().SupportsDatagrams
	if !support.Local || !support.Remote {
		return nil, errors.New("QUIC DATAGRAM is required")
	}
	return c.AcceptStream(ctx)
}

type quicListener struct{ *quic.Listener }

func (l *quicListener) Accept(ctx context.Context) (Conn, error) {
	c, err := l.Listener.Accept(ctx)
	if err != nil {
		return nil, err
	}
	return &quicConn{c}, nil
}

func DialTunnel(ctx context.Context, addr string, cfg *tls.Config, kind string) (Conn, error) {
	return DialTunnelWithControl(ctx, addr, cfg, kind, nil)
}

func DialTunnelWithControl(ctx context.Context, addr string, cfg *tls.Config, kind string, control SocketControl) (Conn, error) {
	switch kind {
	case "", "quic":
		if control != nil {
			peer, err := net.ResolveUDPAddr("udp4", addr)
			if err != nil {
				return nil, err
			}
			lc := net.ListenConfig{Control: control}
			socket, err := lc.ListenPacket(ctx, "udp4", "0.0.0.0:0")
			if err != nil {
				return nil, err
			}
			c, err := quic.Dial(ctx, socket, peer, cfg, QUICConfig())
			if err != nil {
				_ = socket.Close()
				return nil, err
			}
			datagrams := c.ConnectionState().SupportsDatagrams
			if !datagrams.Local || !datagrams.Remote {
				_ = c.CloseWithError(1, "QUIC DATAGRAM is required")
				_ = socket.Close()
				return nil, errors.New("peer does not support QUIC DATAGRAM")
			}
			// A remotely closed connection must also release the owned socket.
			context.AfterFunc(c.Context(), func() { _ = socket.Close() })
			return &ownedQUICConn{quicConn: &quicConn{c}, socket: socket}, nil
		}
		c, err := Dial(ctx, addr, cfg)
		if err != nil {
			return nil, err
		}
		return &quicConn{c}, nil
	case "tcp", "tcp-plain":
		return dialTCPWithControl(ctx, addr, cfg, kind == "tcp", control)
	default:
		return nil, fmt.Errorf("unsupported tunnel transport %q", kind)
	}
}

func ListenTunnel(addr string, cfg *tls.Config, kind string) (Listener, error) {
	switch kind {
	case "", "quic":
		l, err := Listen(addr, cfg)
		if err != nil {
			return nil, err
		}
		return &quicListener{l}, nil
	case "tcp", "tcp-plain":
		return listenTCP(addr, cfg, kind == "tcp")
	default:
		return nil, fmt.Errorf("unsupported tunnel transport %q", kind)
	}
}
