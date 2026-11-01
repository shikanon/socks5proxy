package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/shikanon/socks5proxy/internal/keytable"
	"github.com/shikanon/socks5proxy/internal/tunnel"
	"github.com/shikanon/socks5proxy/internal/tunnel/device"
	tunnelnet "github.com/shikanon/socks5proxy/internal/tunnel/network"
	"github.com/shikanon/socks5proxy/internal/tunnel/protocol"
	"github.com/shikanon/socks5proxy/internal/tunnel/session"
	"github.com/shikanon/socks5proxy/internal/tunnel/transport"
)

type counters struct {
	sent    atomic.Uint64
	recv    atomic.Uint64
	dropped atomic.Uint64
}

func Run(ctx context.Context, config tunnel.ClientConfig) error {
	config.SetDefaults()
	if err := config.Validate(); err != nil {
		return err
	}
	lock, err := tunnelnet.AcquireLock(config.StateDir, "client")
	if err != nil {
		return err
	}
	defer lock.Close()
	// Recover even when credentials have subsequently become invalid.
	restoreCtx, restoreCancel := context.WithTimeout(context.Background(), 15*time.Second)
	err = tunnelnet.RecoverClientState(restoreCtx, config.StateDir, nil)
	restoreCancel()
	if err != nil {
		return fmt.Errorf("recover previous network state: %w", err)
	}
	var table *keytable.Table
	var token string
	if config.Transport == "tcp-table" {
		table, err = keytable.Load(config.TableFile)
	} else {
		token, err = readToken(config.TokenFile)
		if err == nil && len(token) < 32 {
			err = errors.New("client token must contain at least 32 characters")
		}
	}
	if err != nil {
		return err
	}
	obfs, err := tunnel.NormalizeObfs(config.Obfs)
	if err != nil {
		return err
	}
	host, _, _ := net.SplitHostPort(config.ServerAddr)
	serverName := config.ServerName
	if serverName == "" {
		serverName = host
	}
	_, serverPort, _ := net.SplitHostPort(config.ServerAddr)
	var tlsConfig *tls.Config
	if config.Transport != "tcp-plain" && config.Transport != "tcp-table" {
		tlsConfig, err = transport.ClientTLS(config.CAFile, serverName)
		if err != nil {
			return err
		}
	} else if config.Transport == "tcp-plain" {
		log.Print("WARNING: tcp-plain has no packet encryption or integrity; obfuscation is not security")
	} else {
		log.Print("tcp-table uses a learning-only daily substitution table; no TLS or packet integrity")
	}

	var endpoint netip.Addr
	lastMode := ""
	return runWatchdog(ctx, config, watchdogHooks{
		connect: func(ctx context.Context, retained bool) (*connection, error) {
			if !retained || !endpoint.IsValid() {
				var err error
				endpoint, _, err = resolveServer(ctx, config.ServerAddr, config.ServerName)
				if err != nil {
					return nil, err
				}
			}
			dialAddr := net.JoinHostPort(endpoint.String(), serverPort)
			var c transport.Conn
			var response protocol.Message
			var cipher protocol.Cipher
			var err error
			opt := session.Options{IPv6: config.IPv6, Heartbeat: true}
			if table != nil {
				c, response, cipher, err = session.ConnectTable(ctx, dialAddr, config.ClientID, table, nil, opt)
			} else {
				c, response, cipher, err = connect(ctx, dialAddr, config.ClientID, token, obfs, tlsConfig, config.Transport, opt)
			}
			if err != nil {
				return nil, err
			}
			if !response.Heartbeat {
				log.Print("server lacks heartbeat support; health checks use the IP forwarding path")
			}
			healthResponse := response
			if config.DNS != "" {
				healthResponse.DNSIPv4 = config.DNS
			}
			if config.DNSIPv6 != "" {
				healthResponse.DNSIPv6 = config.DNSIPv6
			}
			if err := probe(ctx, c, healthResponse, cipher, healthOptions{interval: config.HealthInterval,
				timeout: config.FallbackTimeout, dnsName: config.HealthDNSName}); err != nil {
				c.CloseWithError(0, "health probe failed")
				return nil, err
			}
			return &connection{conn: c, response: response, cipher: cipher, endpoint: endpoint}, nil
		},
		activate: func(ctx context.Context, c *connection) (managedTunnel, error) { return activate(ctx, config, c) },
		recover:  func(ctx context.Context) error { return tunnelnet.RecoverClientState(ctx, config.StateDir, nil) },
		status: func(mode string, err error) {
			if mode != lastMode || err != nil {
				log.Printf("tunnel watchdog mode=%s error=%v", mode, err)
			}
			lastMode = mode
			if e := tunnelnet.WriteStatus(config.StateDir, mode, err); e != nil {
				log.Printf("write watchdog status: %v", e)
			}
		},
		now: time.Now, wait: waitBackoff,
	})
}

type activeTunnel struct {
	response  protocol.Message
	dev       device.Device
	manager   *tunnelnet.ClientManager
	outbound  chan []byte
	stats     counters
	cancel    context.CancelFunc
	readDone  chan struct{}
	closeOnce sync.Once
	config    tunnel.ClientConfig
}

func activate(ctx context.Context, config tunnel.ClientConfig, c *connection) (managedTunnel, error) {
	r := c.response
	client6, peer6, dns6, err := protocol.ValidateIPv6Parameters(r, config.IPv6)
	if err != nil {
		return nil, err
	}
	if config.DNSIPv6 != "" {
		dns6, _ = netip.ParseAddr(config.DNSIPv6)
	}
	clientIP, e1 := netip.ParseAddr(r.ClientIPv4)
	peerIP, e2 := netip.ParseAddr(r.ServerIPv4)
	dns := r.DNSIPv4
	if config.DNS != "" {
		dns = config.DNS
	}
	dnsIP, e3 := netip.ParseAddr(dns)
	if e1 != nil || !clientIP.Is4() || e2 != nil || !peerIP.Is4() || e3 != nil || !dnsIP.Is4() {
		return nil, errors.New("server returned invalid IPv4 tunnel parameters")
	}
	if r.MTU < 576 || r.MTU > config.MTU {
		return nil, fmt.Errorf("server returned invalid MTU %d", r.MTU)
	}
	dev, err := device.Create(config.TUNName, r.MTU)
	if err != nil {
		return nil, err
	}
	m, err := tunnelnet.NewClientManager(tunnelnet.ClientOptions{
		TUNName: dev.Name(), ClientIP: clientIP, ServerIP: c.endpoint, TunnelPeer: peerIP,
		ClientIPv6: client6, TunnelPeerIPv6: peer6, DNSIPv6: dns6, DNS: dnsIP, MTU: r.MTU,
		StateDir: config.StateDir, SkipLinuxDNS: config.SkipLinuxDNS,
	}, nil)
	if err != nil {
		dev.Close()
		return nil, err
	}
	if err := m.Apply(ctx); err != nil {
		restoreCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		restoreErr := m.Restore(restoreCtx)
		cancel()
		dev.Close()
		return nil, errors.Join(err, restoreErr)
	}
	readerCtx, cancel := context.WithCancel(context.Background())
	a := &activeTunnel{response: r, dev: dev, manager: m, outbound: make(chan []byte, 256), cancel: cancel, readDone: make(chan struct{}), config: config}
	go func() { defer close(a.readDone); readTUN(readerCtx, dev, a.outbound, &a.stats) }()
	log.Printf("global tunnel enabled interface=%s client_ip=%s server_ip=%s transport=%s", dev.Name(), clientIP, c.endpoint, config.Transport)
	return a, nil
}

func (a *activeTunnel) parameters() protocol.Message { return a.response }
func (a *activeTunnel) relay(ctx context.Context, c *connection) error {
	r := c.response
	if a.config.DNS != "" {
		r.DNSIPv4 = a.config.DNS
	}
	if a.config.DNSIPv6 != "" {
		r.DNSIPv6 = a.config.DNSIPv6
	}
	return relay(ctx, c.conn, a.dev, a.outbound, r, c.cipher, &a.stats,
		healthOptions{interval: a.config.HealthInterval, timeout: a.config.FallbackTimeout, dnsName: a.config.HealthDNSName})
}
func (a *activeTunnel) restore(ctx context.Context) error {
	err := a.manager.Restore(ctx)
	a.closeOnce.Do(func() { a.cancel(); _ = a.dev.Close(); <-a.readDone })
	return err
}

func connect(
	ctx context.Context,
	serverAddr, clientID, token, obfs string,
	tlsConfig *tls.Config,
	kind string,
	options ...session.Options,
) (result transport.Conn, response protocol.Message, cipher protocol.Cipher, err error) {
	return session.Connect(ctx, serverAddr, clientID, token, obfs, tlsConfig, kind, nil, options...)
}

func relay(
	ctx context.Context,
	conn transport.Conn,
	tunDevice device.Device,
	outbound <-chan []byte,
	response protocol.Message,
	cipher protocol.Cipher,
	stats *counters,
	health ...healthOptions,
) error {
	clientIP := netip.MustParseAddr(response.ClientIPv4)
	client6, _ := netip.ParseAddr(response.ClientIPv6)
	mtu := response.MTU
	childCtx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	defer func() {
		cancel()
		_ = conn.CloseWithError(0, "relay stopped")
		workers.Wait()
	}()

	errs := make(chan error, 3)
	var monitor *healthMonitor
	if response.Heartbeat || len(health) > 0 {
		options := healthOptions{interval: tunnel.DefaultHealthInterval, timeout: tunnel.DefaultFallbackTimeout}
		if len(health) > 0 {
			options = health[0]
		}
		if len(health) > 0 {
			var err error
			monitor, err = newConnectionHealth(response, cipher, options)
			if err != nil {
				return err
			}
		} else {
			monitor = newHealthMonitor(options)
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			if err := monitor.run(childCtx, conn); err != nil {
				errs <- err
			}
		}()
	}
	workers.Add(2)
	go func() {
		defer workers.Done()
		for {
			var packet []byte
			select {
			case <-childCtx.Done():
				return
			case packet = <-outbound:
			}
			if childCtx.Err() != nil {
				return
			}
			payload, info, err := protocol.EncodeDatagram(packet, mtu, cipher)
			if err != nil || !protocol.MatchesLease(info.Source, clientIP, client6) {
				stats.dropped.Add(1)
				continue
			}
			if err := conn.SendDatagram(payload); err != nil {
				var tooLarge *quic.DatagramTooLargeError
				if errors.As(err, &tooLarge) {
					stats.dropped.Add(1)
					continue
				}
				errs <- err
				return
			}
			stats.sent.Add(uint64(len(packet)))
		}
	}()
	go func() {
		defer workers.Done()
		for {
			payload, err := conn.ReceiveDatagram(childCtx)
			if err != nil {
				errs <- err
				return
			}
			if kind, nonce, ok := protocol.ParseHeartbeat(payload); ok {
				if monitor != nil && kind == protocol.DatagramTypePong {
					monitor.pong(nonce)
				}
				continue
			}
			packet, info, err := protocol.DecodeDatagram(payload, mtu, cipher)
			if err != nil || !protocol.MatchesLease(info.Destination, clientIP, client6) {
				stats.dropped.Add(1)
				continue
			}
			if monitor != nil && monitor.packet(packet) {
				continue
			}
			if err := tunDevice.WritePacket(packet); err != nil {
				errs <- err
				return
			}
			stats.recv.Add(uint64(len(packet)))
		}
	}()

	finish := func(err error) error {
		if ctx.Err() == nil && monitor != nil && monitor.expired() {
			return errors.Join(errHealthTimeout, err)
		}
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errs:
		return finish(err)
	case <-conn.Context().Done():
		return finish(context.Cause(conn.Context()))
	}
}

func readTUN(ctx context.Context, tunDevice device.Device, outbound chan<- []byte, stats *counters) {
	for {
		packet, err := tunDevice.ReadPacket()
		if err != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case outbound <- packet:
		default:
			stats.dropped.Add(1)
		}
	}
}

func resolveServer(ctx context.Context, serverAddr, configuredName string) (netip.Addr, string, error) {
	host, _, err := net.SplitHostPort(serverAddr)
	if err != nil {
		return netip.Addr{}, "", err
	}
	serverName := configuredName
	if serverName == "" {
		serverName = host
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		addr = addr.Unmap()
		if !addr.IsValid() || addr.IsUnspecified() || addr.IsMulticast() || addr.Zone() != "" {
			return netip.Addr{}, "", errors.New("invalid tunnel server endpoint")
		}
		return addr, serverName, nil
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.Addr{}, "", fmt.Errorf("resolve tunnel server %q: %w", host, err)
	}
	for _, addr := range addrs {
		if addr.Unmap().Is4() {
			return addr.Unmap(), serverName, nil
		}
	}
	if len(addrs) > 0 {
		return addrs[0], serverName, nil
	}
	return netip.Addr{}, "", fmt.Errorf("no addresses for tunnel server %q", host)
}

func readToken(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("stat client token file: %w", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("client token file must not be accessible by group or others")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read client token file: %w", err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", errors.New("client token file is empty")
	}
	return token, nil
}

func waitBackoff(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func sameTunnelParameters(a, b protocol.Message) bool {
	return protocol.SameTunnelParameters(a, b)
}
