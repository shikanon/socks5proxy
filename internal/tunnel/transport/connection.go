package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
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
	switch kind {
	case "", "quic":
		c, err := Dial(ctx, addr, cfg)
		if err != nil {
			return nil, err
		}
		return &quicConn{c}, nil
	case "tcp", "tcp-plain":
		return dialTCP(ctx, addr, cfg, kind == "tcp")
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
