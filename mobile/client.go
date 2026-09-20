package mobile

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/shikanon/socks5proxy/internal/tunnel/protocol"
	"github.com/shikanon/socks5proxy/internal/tunnel/session"
	"github.com/shikanon/socks5proxy/internal/tunnel/transport"
)

// SocketProtector must protect the fd synchronously before returning.
// Android passes VpnService.protect; iOS passes nil (provider sockets bypass VPN).
type SocketProtector interface {
	ProtectSocket(fd int) bool
}

// Client is single-use. Create a new instance after Close or a terminal error.
// All exported methods are safe to call from different native threads.
type Client struct {
	config    config
	tls       *tls.Config
	control   transport.SocketControl
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	state     string
	lastError string
	conn      transport.Conn
	cipher    protocol.Cipher
	params    parameters
	dialAddr  string
	closeFD   func()
	outbound  chan []byte
	inbound   chan []byte
	sent      atomic.Uint64
	received  atomic.Uint64
	dropped   atomic.Uint64
}

func NewClient(configJSON string, protector SocketProtector) (*Client, error) {
	cfg, err := parseConfig(configJSON)
	if err != nil {
		return nil, err
	}
	tlsConfig, err := cfg.tlsConfig()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := &Client{
		config: cfg, tls: tlsConfig, ctx: ctx, cancel: cancel, state: "new",
		outbound: make(chan []byte, 256), inbound: make(chan []byte, 256),
	}
	if protector != nil {
		c.control = func(_, _ string, raw syscall.RawConn) error {
			protected := false
			if err := raw.Control(func(fd uintptr) { protected = protector.ProtectSocket(int(fd)) }); err != nil {
				return err
			}
			if !protected {
				return errors.New("VPN socket protection failed")
			}
			return nil
		}
	}
	return c, nil
}

// Connect authenticates before the OS installs VPN routes. The result is JSON
// containing the negotiated addresses, endpoint_ipv4 and MTU.
func (c *Client) Connect() (string, error) {
	c.mu.Lock()
	if c.state != "new" {
		c.mu.Unlock()
		return "", errors.New("client already connected or closed")
	}
	c.state = "connecting"
	c.mu.Unlock()
	host, port, _ := net.SplitHostPort(c.config.ServerAddr)
	resolveCtx, cancel := context.WithTimeout(c.ctx, 10*time.Second)
	addrs, err := net.DefaultResolver.LookupNetIP(resolveCtx, "ip4", host)
	cancel()
	if err != nil || len(addrs) == 0 {
		err = fmt.Errorf("resolve IPv4 endpoint %q: %v", host, err)
		c.fail(err)
		return "", err
	}
	endpoint := addrs[0].Unmap().String()
	dialAddr := net.JoinHostPort(endpoint, port)
	conn, response, cipher, err := session.Connect(c.ctx, dialAddr, c.config.ClientID, c.config.Token, c.config.Obfs, c.tls, c.config.Transport, c.control)
	if err != nil {
		c.fail(err)
		return "", err
	}
	p, err := c.config.parameters(response, endpoint)
	if err != nil {
		_ = conn.CloseWithError(4, "invalid tunnel parameters")
		c.fail(err)
		return "", err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ctx.Err() != nil {
		_ = conn.CloseWithError(0, "client closed")
		return "", c.ctx.Err()
	}
	c.conn, c.cipher, c.params, c.dialAddr = conn, cipher, p, dialAddr
	c.state = "ready"
	raw, _ := json.Marshal(p)
	return string(raw), nil
}

// Start begins relaying after the caller has configured the native VPN.
func (c *Client) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != "ready" || c.ctx.Err() != nil {
		return errors.New("client must be connected before Start")
	}
	c.state = "connected"
	go c.run(c.conn, c.cipher)
	return nil
}

// WritePacket copies one raw IPv4 packet from the OS. Under congestion packets
// are dropped instead of blocking the native VPN callback.
func (c *Client) WritePacket(packet []byte) error {
	if c.ctx.Err() != nil {
		return c.ctx.Err()
	}
	if len(packet) < 20 || len(packet) > 1400 || packet[0]>>4 != 4 {
		c.dropped.Add(1)
		return nil
	}
	copy := append([]byte(nil), packet...)
	select {
	case <-c.ctx.Done():
		return c.ctx.Err()
	case c.outbound <- copy:
	default:
		c.dropped.Add(1)
	}
	return nil
}

// ReadPacket blocks until one raw IPv4 packet arrives or Close is called.
// Use a background thread, never the UI thread.
func (c *Client) ReadPacket() ([]byte, error) {
	if c.ctx.Err() != nil {
		return nil, c.ctx.Err()
	}
	select {
	case <-c.ctx.Done():
		return nil, c.ctx.Err()
	case packet := <-c.inbound:
		return packet, nil
	}
}

func (c *Client) Status() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	data, _ := json.Marshal(struct {
		State    string `json:"state"`
		Error    string `json:"error"`
		Sent     uint64 `json:"sent_bytes"`
		Received uint64 `json:"received_bytes"`
		Dropped  uint64 `json:"dropped_packets"`
	}{c.state, c.lastError, c.sent.Load(), c.received.Load(), c.dropped.Load()})
	return string(data)
}

func (c *Client) Close() error {
	c.shutdown(nil)
	return nil
}

func (c *Client) fail(err error) { c.shutdown(err) }

func (c *Client) shutdown(err error) {
	c.mu.Lock()
	if c.ctx.Err() != nil {
		c.mu.Unlock()
		return
	}
	c.cancel()
	c.state = "closed"
	if err != nil {
		c.state, c.lastError = "error", err.Error()
	}
	conn, closeFD := c.conn, c.closeFD
	c.mu.Unlock()
	if conn != nil {
		_ = conn.CloseWithError(0, "client stopped")
	}
	if closeFD != nil {
		closeFD()
	}
}

func (c *Client) run(conn transport.Conn, cipher protocol.Cipher) {
	for {
		err := c.relay(conn, cipher)
		_ = conn.CloseWithError(0, "reconnecting")
		if c.ctx.Err() != nil {
			return
		}
		c.mu.Lock()
		if c.ctx.Err() != nil {
			c.mu.Unlock()
			return
		}
		c.state, c.lastError = "reconnecting", err.Error()
		c.mu.Unlock()
		backoff := time.Second
		for {
			timer := time.NewTimer(backoff + time.Duration(rand.Int64N(int64(backoff/2)+1)))
			select {
			case <-c.ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			var response protocol.Message
			conn, response, cipher, err = session.Connect(c.ctx, c.dialAddr, c.config.ClientID, c.config.Token, c.config.Obfs, c.tls, c.config.Transport, c.control)
			if err != nil {
				c.mu.Lock()
				if c.ctx.Err() == nil {
					c.lastError = err.Error()
				}
				c.mu.Unlock()
				backoff = min(backoff*2, 30*time.Second)
				continue
			}
			p, err := c.config.parameters(response, c.params.EndpointIPv4)
			if err != nil || p != c.params {
				_ = conn.CloseWithError(6, "tunnel parameters changed")
				c.fail(errors.New("server changed tunnel parameters; reconnect the VPN"))
				return
			}
			c.mu.Lock()
			if c.ctx.Err() != nil {
				c.mu.Unlock()
				_ = conn.CloseWithError(0, "client stopped")
				return
			}
			c.conn, c.state, c.lastError = conn, "connected", ""
			c.mu.Unlock()
			break
		}
	}
}

func (c *Client) relay(conn transport.Conn, cipher protocol.Cipher) error {
	ctx, cancel := context.WithCancel(c.ctx)
	var wg sync.WaitGroup
	defer func() {
		cancel()
		_ = conn.CloseWithError(0, "relay stopped")
		wg.Wait()
	}()
	errs := make(chan error, 2)
	clientIP := netip.MustParseAddr(c.params.ClientIPv4)
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case packet := <-c.outbound:
				payload, info, err := protocol.EncodeDatagram(packet, c.params.MTU, cipher)
				if err != nil || info.Source != clientIP {
					c.dropped.Add(1)
					continue
				}
				if err = conn.SendDatagram(payload); err != nil {
					var tooLarge *quic.DatagramTooLargeError
					if errors.As(err, &tooLarge) {
						c.dropped.Add(1)
						continue
					}
					errs <- err
					return
				}
				c.sent.Add(uint64(len(packet)))
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			payload, err := conn.ReceiveDatagram(ctx)
			if err != nil {
				errs <- err
				return
			}
			packet, info, err := protocol.DecodeDatagram(payload, c.params.MTU, cipher)
			if err != nil || info.Destination != clientIP {
				c.dropped.Add(1)
				continue
			}
			select {
			case <-ctx.Done():
				return
			case c.inbound <- packet:
				c.received.Add(uint64(len(packet)))
			default:
				c.dropped.Add(1)
			}
		}
	}()
	select {
	case <-c.ctx.Done():
		return c.ctx.Err()
	case err := <-errs:
		return err
	case <-conn.Context().Done():
		return context.Cause(conn.Context())
	}
}
