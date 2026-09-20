package transport

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/shikanon/socks5proxy/internal/tunnel/protocol"
)

const maxTCPDatagram = 1402

type tcpConn struct {
	wire      net.Conn
	raw       net.Conn
	ctx       context.Context
	cancel    context.CancelCauseFunc
	closeOnce sync.Once
	startOnce sync.Once
	control   atomic.Bool
	started   atomic.Bool
	writeMu   sync.Mutex
	readMu    sync.Mutex
}

func newTCPConn(wire, raw net.Conn) *tcpConn {
	ctx, cancel := context.WithCancelCause(context.Background())
	return &tcpConn{wire: wire, raw: raw, ctx: ctx, cancel: cancel}
}

func tcpTLSConfig(cfg *tls.Config, client bool) (*tls.Config, error) {
	if cfg == nil {
		return nil, errors.New("TCP TLS configuration is required")
	}
	if client && cfg.InsecureSkipVerify {
		return nil, errors.New("TCP TLS requires certificate verification")
	}
	copy := cfg.Clone()
	copy.MinVersion, copy.MaxVersion = tls.VersionTLS13, tls.VersionTLS13
	return copy, nil
}

func dialTCPWithControl(ctx context.Context, addr string, cfg *tls.Config, secure bool, control SocketControl) (Conn, error) {
	var err error
	if secure {
		cfg, err = tcpTLSConfig(cfg, true)
		if err != nil {
			return nil, err
		}
	}
	dialCtx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	raw, err := (&net.Dialer{KeepAlive: keepAlivePeriod, Control: control}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	var wire net.Conn = raw
	if secure {
		tc := tls.Client(raw, cfg)
		if err = tc.HandshakeContext(dialCtx); err == nil && tc.ConnectionState().NegotiatedProtocol != protocol.ALPN {
			err = errors.New("TCP TLS peer did not negotiate tunnel ALPN")
		}
		if err != nil {
			_ = raw.Close()
			return nil, err
		}
		wire = tc
	}
	return newTCPConn(wire, raw), nil
}

type tcpListener struct {
	net.Listener
	tlsConfig *tls.Config
}

func listenTCP(addr string, cfg *tls.Config, secure bool) (Listener, error) {
	var err error
	if secure {
		cfg, err = tcpTLSConfig(cfg, false)
		if err != nil {
			return nil, err
		}
	} else {
		cfg = nil
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &tcpListener{Listener: l, tlsConfig: cfg}, nil
}

func (l *tcpListener) Accept(ctx context.Context) (Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = l.Close() })
	defer stop()
	raw, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		_ = raw.Close()
		return nil, ctx.Err()
	}
	if tc, ok := raw.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(keepAlivePeriod)
	}
	var wire net.Conn = raw
	if l.tlsConfig != nil {
		wire = tls.Server(raw, l.tlsConfig)
	}
	// TLS runs in AcceptControl, so a stalled handshake cannot block Accept.
	return newTCPConn(wire, raw), nil
}

func (c *tcpConn) Context() context.Context { return c.ctx }

func (c *tcpConn) fail(err error) error {
	c.closeOnce.Do(func() {
		c.cancel(err)
		// Close the socket directly to interrupt concurrent TLS and packet I/O.
		_ = c.raw.Close()
	})
	return err
}

func (c *tcpConn) CloseWithError(_ quic.ApplicationErrorCode, reason string) error {
	c.fail(errors.New(reason))
	return nil
}

func (c *tcpConn) OpenControl(ctx context.Context) (ControlStream, error) {
	return c.openControl(ctx)
}

func (c *tcpConn) AcceptControl(ctx context.Context) (ControlStream, error) {
	return c.openControl(ctx)
}

func (c *tcpConn) openControl(ctx context.Context) (ControlStream, error) {
	if !c.control.CompareAndSwap(false, true) {
		return nil, errors.New("TCP control stream already opened")
	}
	authCtx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	stop := context.AfterFunc(authCtx, func() { c.fail(authCtx.Err()) })
	deadline, _ := authCtx.Deadline()
	if err := c.wire.SetDeadline(deadline); err != nil {
		stop()
		cancel()
		return nil, c.fail(err)
	}
	if tc, ok := c.wire.(*tls.Conn); ok {
		err := tc.HandshakeContext(authCtx)
		if err == nil && tc.ConnectionState().NegotiatedProtocol != protocol.ALPN {
			err = errors.New("TCP TLS peer did not negotiate tunnel ALPN")
		}
		if err != nil {
			stop()
			cancel()
			return nil, c.fail(err)
		}
	}
	return &tcpControl{Conn: c.wire, owner: c, ctx: authCtx, cancel: cancel, stop: stop}, nil
}

type tcpControl struct {
	net.Conn
	owner  *tcpConn
	ctx    context.Context
	cancel context.CancelFunc
	stop   func() bool
	once   sync.Once
	err    error
}

// Closing control starts framed packet mode; it does not close the socket.
func (s *tcpControl) Close() error {
	s.once.Do(func() {
		s.stop()
		err := s.ctx.Err()
		s.cancel()
		if err != nil {
			s.err = s.owner.fail(err)
			return
		}
		s.err = s.owner.startData()
	})
	return s.err
}

func (c *tcpConn) startData() error {
	var err error
	c.startOnce.Do(func() {
		if err = c.wire.SetDeadline(time.Time{}); err != nil {
			c.fail(err)
			return
		}
		c.started.Store(true)
		go func() {
			ticker := time.NewTicker(keepAlivePeriod)
			defer ticker.Stop()
			for {
				select {
				case <-c.ctx.Done():
					return
				case <-ticker.C:
					if c.sendFrame(nil) != nil {
						return
					}
				}
			}
		}()
	})
	return err
}

func writeFrame(w io.Writer, payload []byte) error {
	if len(payload) > maxTCPDatagram {
		return errors.New("TCP tunnel packet exceeds 1402 bytes")
	}
	frame := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(frame, uint16(len(payload)))
	copy(frame[2:], payload)
	for len(frame) > 0 {
		n, err := w.Write(frame)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(frame) {
			return io.ErrShortWrite
		}
		frame = frame[n:]
	}
	return nil
}

func (c *tcpConn) sendFrame(payload []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.ctx.Err(); err != nil {
		return err
	}
	if err := c.wire.SetWriteDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return c.fail(err)
	}
	if err := writeFrame(c.wire, payload); err != nil {
		return c.fail(err)
	}
	return nil
}

func (c *tcpConn) SendDatagram(payload []byte) error {
	if !c.started.Load() {
		return errors.New("TCP packet mode has not started")
	}
	if len(payload) == 0 || len(payload) > maxTCPDatagram {
		return errors.New("invalid TCP tunnel packet size")
	}
	return c.sendFrame(payload)
}

func (c *tcpConn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	if !c.started.Load() {
		return nil, errors.New("TCP packet mode has not started")
	}
	if err := ctx.Err(); err != nil {
		return nil, c.fail(err)
	}
	stop := context.AfterFunc(ctx, func() { c.fail(ctx.Err()) })
	defer stop()
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for {
		if err := c.wire.SetReadDeadline(time.Now().Add(idleTimeout)); err != nil {
			return nil, c.fail(err)
		}
		var header [2]byte
		if _, err := io.ReadFull(c.wire, header[:]); err != nil {
			return nil, c.fail(err)
		}
		size := int(binary.BigEndian.Uint16(header[:]))
		if size > maxTCPDatagram {
			return nil, c.fail(errors.New("oversized TCP tunnel frame"))
		}
		if size == 0 {
			continue
		}
		payload := make([]byte, size)
		if _, err := io.ReadFull(c.wire, payload); err != nil {
			return nil, c.fail(err)
		}
		return payload, nil
	}
}
