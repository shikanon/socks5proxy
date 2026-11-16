package mesh

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

type Node struct {
	config      Config
	tls         *tls.Config
	mu          sync.Mutex
	dialSlot    chan struct{}
	peers       map[string]Member
	sessions    map[string]*quic.Conn
	incoming    map[*quic.Conn]bool
	expires     map[string]time.Time
	listener    *quic.Listener
	closed      bool
	streamSlots chan struct{}
}

func NewNode(c Config) (*Node, error) {
	if e := c.Validate(); e != nil {
		return nil, e
	}
	// Own an immutable copy; callers cannot mutate ACLs while traffic is active.
	data, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	c = Config{}
	if err = json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	t, e := TLS(c, true)
	if e != nil {
		return nil, e
	}
	n := &Node{config: c, tls: t, peers: map[string]Member{}, sessions: map[string]*quic.Conn{}, incoming: map[*quic.Conn]bool{}, expires: map[string]time.Time{}, streamSlots: make(chan struct{}, 128), dialSlot: make(chan struct{}, 1)}
	if c.ControlURL == "" {
		for _, m := range c.Members {
			n.peers[m.IP] = m
		}
	}
	return n, nil
}
func quicConfig() *quic.Config {
	return &quic.Config{HandshakeIdleTimeout: 8 * time.Second, MaxIdleTimeout: 45 * time.Second, KeepAlivePeriod: 15 * time.Second, MaxIncomingStreams: 128, MaxIncomingUniStreams: -1, Allow0RTT: false}
}

// Refresh never accepts identities, IPs, service ports or endpoints outside the trusted local inventory.
func (n *Node) Refresh(ctx context.Context) error {
	leases, e := Peers(ctx, n.config)
	if e != nil {
		return e
	}
	next := map[string]Member{}
	expires := map[string]time.Time{}
	now := time.Now()
	for _, l := range leases {
		if !l.Expires.After(now) || l.Expires.After(now.Add(2*leaseTime)) {
			continue
		}
		for _, m := range n.config.Members {
			if m.ID != l.ID || m.IP != l.IP {
				continue
			}
			p := m
			p.Endpoints = nil
			for _, a := range l.Endpoints {
				if contains(m.Endpoints, a) {
					p.Endpoints = append(p.Endpoints, a)
				}
			}
			if len(p.Endpoints) > 0 {
				next[p.IP] = p
				expires[p.IP] = l.Expires
			}
		}
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return net.ErrClosed
	}
	n.peers = next
	n.expires = expires
	return nil
}
func (n *Node) Run(ctx context.Context) error {
	if n.config.Listen == "" {
		return errors.New("node listener required")
	}
	l, e := quic.ListenAddr(n.config.Listen, n.tls, quicConfig())
	if e != nil {
		return e
	}
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		l.Close()
		return net.ErrClosed
	}
	n.listener = l
	n.mu.Unlock()
	stop := context.AfterFunc(ctx, func() { n.Close() })
	defer stop()
	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()
	defer n.Close()
	if n.config.ControlURL != "" {
		go n.renew(runCtx)
	}
	for {
		c, e := l.Accept(ctx)
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			return e
		}
		id, e := identity(c.ConnectionState().TLS)
		known := false
		for _, m := range n.config.Members {
			if m.ID == id {
				known = true
			}
		}
		if e != nil || !known {
			c.CloseWithError(1, "not authorized")
			continue
		}
		n.mu.Lock()
		if len(n.incoming) >= 128 {
			n.mu.Unlock()
			c.CloseWithError(1, "connection limit")
			continue
		}
		if n.closed {
			n.mu.Unlock()
			c.CloseWithError(0, "closed")
			return nil
		}
		n.incoming[c] = true
		n.mu.Unlock()
		go n.acceptStreams(ctx, c, id)
	}
}
func (n *Node) renew(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		if n.config.Endpoint != "" {
			_ = Register(ctx, n.config)
		}
		_ = n.Refresh(ctx)
		timer := time.NewTimer(30 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
func (n *Node) acceptStreams(ctx context.Context, c *quic.Conn, id string) {
	defer func() { n.mu.Lock(); delete(n.incoming, c); n.mu.Unlock(); c.CloseWithError(0, "closed") }()
	slots := make(chan struct{}, 128)
	for {
		select {
		case slots <- struct{}{}:
		case <-c.Context().Done():
			return
		case <-ctx.Done():
			c.CloseWithError(0, "stopped")
			return
		}
		s, e := c.AcceptStream(ctx)
		if e != nil {
			<-slots
			return
		}
		go func() {
			defer func() { <-slots }()
			select {
			case n.streamSlots <- struct{}{}:
				defer func() { <-n.streamSlots }()
				n.serveStream(ctx, s, id)
			default:
				s.CancelRead(1)
				s.CancelWrite(1)
			}
		}()
	}
}
func (n *Node) serveStream(ctx context.Context, s *quic.Stream, id string) {
	defer s.Close()
	defer s.CancelRead(0)
	_ = s.SetDeadline(time.Now().Add(8 * time.Second))
	var header [3]byte
	if _, e := io.ReadFull(s, header[:]); e != nil {
		return
	}
	port := binary.BigEndian.Uint16(header[1:])
	var target string
	if header[0] == 1 {
		for _, v := range n.config.Services {
			if v.Port == port && contains(v.Allow, id) {
				target = v.Target
				break
			}
		}
	}
	if target == "" {
		_, _ = s.Write([]byte{1})
		return
	}
	dialer := net.Dialer{Timeout: 5 * time.Second}
	local, e := dialer.DialContext(ctx, "tcp", target)
	if e != nil {
		_, _ = s.Write([]byte{2})
		return
	}
	defer local.Close()
	if _, e = s.Write([]byte{0}); e != nil {
		return
	}
	_ = s.SetDeadline(time.Time{})
	conn := &streamConn{stream: s, local: local.LocalAddr(), remote: local.RemoteAddr()}
	relay(ctx, conn, local)
}
func (n *Node) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" {
		return nil, errors.New("mesh service overlay supports TCP streams only")
	}
	host, p, e := net.SplitHostPort(address)
	if e != nil {
		return nil, e
	}
	port, e := strconv.ParseUint(p, 10, 16)
	if e != nil || port == 0 {
		return nil, errors.New("invalid virtual port")
	}
	n.mu.Lock()
	member, ok := n.peers[host]
	closed := n.closed
	expiry := n.expires[host]
	n.mu.Unlock()
	if n.config.ControlURL != "" && (expiry.IsZero() || !expiry.After(time.Now())) {
		return nil, errors.New("virtual node lease expired")
	}
	if closed {
		return nil, net.ErrClosed
	}
	if !ok {
		return nil, errors.New("virtual node unknown or lease expired")
	}
	allowed := false
	for _, v := range member.Ports {
		if uint64(v) == port {
			allowed = true
		}
	}
	if !allowed {
		return nil, errors.New("virtual service not advertised")
	}
	session, e := n.session(ctx, member)
	if e != nil {
		return nil, e
	}
	s, e := session.OpenStreamSync(ctx)
	if e != nil {
		return nil, e
	}
	// The service header is control-only. No caller payload is sent before acceptance.
	deadline := time.Now().Add(8 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = s.SetDeadline(deadline)
	cancel := context.AfterFunc(ctx, func() { s.CancelRead(1); s.CancelWrite(1) })
	defer cancel()
	var header [3]byte
	header[0] = 1
	binary.BigEndian.PutUint16(header[1:], uint16(port))
	if _, e = s.Write(header[:]); e == nil {
		var status [1]byte
		_, e = io.ReadFull(s, status[:])
		if e == nil && status[0] != 0 {
			e = errors.New("mesh service refused")
		}
	}
	if e != nil {
		s.CancelRead(1)
		s.CancelWrite(1)
		return nil, e
	}
	_ = s.SetDeadline(time.Time{})
	return &streamConn{stream: s, local: session.LocalAddr(), remote: session.RemoteAddr()}, nil
}
func (n *Node) session(ctx context.Context, m Member) (*quic.Conn, error) {
	select {
	case n.dialSlot <- struct{}{}:
		defer func() { <-n.dialSlot }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return nil, net.ErrClosed
	}
	c := n.sessions[m.ID]
	n.mu.Unlock()
	if c != nil && c.Context().Err() == nil {
		return c, nil
	}
	cfg := n.tls.Clone()
	cfg.ClientAuth = tls.NoClientCert
	cfg.ServerName = m.ID
	var last error
	for _, a := range m.Endpoints {
		attempt, cancel := context.WithTimeout(ctx, 8*time.Second)
		c, e := quic.DialAddr(attempt, a, cfg, quicConfig())
		cancel()
		if e != nil {
			last = e
			continue
		}
		id, e := identity(c.ConnectionState().TLS)
		if e != nil || id != m.ID {
			c.CloseWithError(1, "peer mismatch")
			last = errors.New("peer mismatch")
			continue
		}
		n.mu.Lock()
		if n.closed {
			n.mu.Unlock()
			c.CloseWithError(0, "closed")
			return nil, net.ErrClosed
		}
		n.sessions[m.ID] = c
		n.mu.Unlock()
		return c, nil
	}
	if last == nil {
		last = errors.New("no authorized endpoint")
	}
	return nil, fmt.Errorf("mesh dial: %w", last)
}
func (n *Node) Close() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return nil
	}
	n.closed = true
	if n.listener != nil {
		_ = n.listener.Close()
	}
	for _, c := range n.sessions {
		_ = c.CloseWithError(0, "closed")
	}
	for c := range n.incoming {
		_ = c.CloseWithError(0, "closed")
	}
	return nil
}

type streamConn struct {
	stream        *quic.Stream
	local, remote net.Addr
}

func (c *streamConn) Read(p []byte) (int, error)  { return c.stream.Read(p) }
func (c *streamConn) Write(p []byte) (int, error) { return c.stream.Write(p) }
func (c *streamConn) Close() error {
	c.stream.CancelRead(0)
	c.stream.CancelWrite(0)
	return nil
}
func (c *streamConn) CloseWrite() error                  { return c.stream.Close() }
func (c *streamConn) LocalAddr() net.Addr                { return c.local }
func (c *streamConn) RemoteAddr() net.Addr               { return c.remote }
func (c *streamConn) SetDeadline(t time.Time) error      { return c.stream.SetDeadline(t) }
func (c *streamConn) SetReadDeadline(t time.Time) error  { return c.stream.SetReadDeadline(t) }
func (c *streamConn) SetWriteDeadline(t time.Time) error { return c.stream.SetWriteDeadline(t) }
func relay(ctx context.Context, a, b net.Conn) {
	var mu sync.Mutex
	touch := func() {
		mu.Lock()
		defer mu.Unlock()
		d := time.Now().Add(300 * time.Second)
		_ = a.SetDeadline(d)
		_ = b.SetDeadline(d)
	}
	touch()
	stop := context.AfterFunc(ctx, func() { a.Close(); b.Close() })
	defer stop()
	done := make(chan struct{}, 2)
	copyOne := func(dst, src net.Conn) {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 32768)
		for {
			count, e := src.Read(buf)
			if count > 0 {
				touch()
				offset := 0
				for offset < count {
					w, err := dst.Write(buf[offset:count])
					if err != nil || w == 0 {
						a.Close()
						b.Close()
						return
					}
					offset += w
					touch()
				}
			}
			if e != nil {
				if e == io.EOF {
					if h, ok := dst.(interface{ CloseWrite() error }); ok {
						_ = h.CloseWrite()
					} else {
						_ = dst.Close()
					}
				} else {
					a.Close()
					b.Close()
				}
				return
			}
		}
	}
	go copyOne(a, b)
	go copyOne(b, a)
	<-done
	<-done
}
