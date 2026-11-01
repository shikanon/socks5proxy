package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
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
	var table *keytable.Table
	var token string
	var err error
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
	if err := tunnelnet.RecoverClientState(ctx, config.StateDir, nil); err != nil {
		return fmt.Errorf("recover previous network state: %w", err)
	}
	obfs, err := tunnel.NormalizeObfs(config.Obfs)
	if err != nil {
		return err
	}
	serverIP, serverName, err := resolveServer(ctx, config.ServerAddr, config.ServerName)
	if err != nil {
		return err
	}
	_, serverPort, _ := net.SplitHostPort(config.ServerAddr)
	dialAddr := net.JoinHostPort(serverIP.String(), serverPort)
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

	var (
		tunDevice      device.Device
		networkManager *tunnelnet.ClientManager
		networkApplied bool
		stats          counters
		outbound       chan []byte
		activeResponse protocol.Message
	)
	defer func() {
		if networkApplied && networkManager != nil {
			restoreCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if err := networkManager.Restore(restoreCtx); err != nil {
				log.Printf("tunnel client network restore failed: %v", err)
			}
		}
		if tunDevice != nil {
			_ = tunDevice.Close()
		}
	}()

	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return nil
		}
		var conn transport.Conn
		var response protocol.Message
		var cipher protocol.Cipher
		if table != nil {
			conn, response, cipher, err = session.ConnectTable(ctx, dialAddr, config.ClientID, table, nil, session.Options{IPv6: config.IPv6})
		} else {
			conn, response, cipher, err = connect(ctx, dialAddr, config.ClientID, token, obfs, tlsConfig, config.Transport, session.Options{IPv6: config.IPv6})
		}
		if err != nil {
			if !networkApplied {
				return err
			}
			log.Printf("tunnel reconnect failed: %v", err)
			if err := waitBackoff(ctx, backoff); err != nil {
				return nil
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}

		if !networkApplied {
			client6, peer6, dns6, err := protocol.ValidateIPv6Parameters(response, config.IPv6)
			if err != nil {
				_ = conn.CloseWithError(4, "invalid IPv6 parameters")
				return err
			}
			if config.DNSIPv6 != "" {
				dns6, _ = netip.ParseAddr(config.DNSIPv6)
			}
			clientIP, err := netip.ParseAddr(response.ClientIPv4)
			if err != nil || !clientIP.Is4() {
				_ = conn.CloseWithError(4, "invalid client address")
				return errors.New("server returned an invalid client IPv4 address")
			}
			peerIP, err := netip.ParseAddr(response.ServerIPv4)
			if err != nil || !peerIP.Is4() {
				_ = conn.CloseWithError(4, "invalid server address")
				return errors.New("server returned an invalid tunnel peer address")
			}
			dnsIP, err := netip.ParseAddr(response.DNSIPv4)
			if config.DNS != "" {
				dnsIP, err = netip.ParseAddr(config.DNS)
			}
			if err != nil || !dnsIP.Is4() {
				_ = conn.CloseWithError(4, "invalid DNS address")
				return errors.New("server returned an invalid DNS address")
			}
			if response.MTU < 576 || response.MTU > config.MTU {
				_ = conn.CloseWithError(4, "invalid MTU")
				return fmt.Errorf("server returned invalid MTU %d", response.MTU)
			}
			tunDevice, err = device.Create(config.TUNName, response.MTU)
			if err != nil {
				_ = conn.CloseWithError(5, "TUN creation failed")
				return err
			}
			networkManager, err = tunnelnet.NewClientManager(tunnelnet.ClientOptions{
				TUNName:        tunDevice.Name(),
				ClientIP:       clientIP,
				ServerIP:       serverIP,
				TunnelPeer:     peerIP,
				ClientIPv6:     client6,
				TunnelPeerIPv6: peer6,
				DNSIPv6:        dns6,
				DNS:            dnsIP,
				MTU:            response.MTU,
				StateDir:       config.StateDir,
				SkipLinuxDNS:   config.SkipLinuxDNS,
			}, nil)
			if err != nil {
				_ = conn.CloseWithError(5, "network setup failed")
				return err
			}
			if err := networkManager.Recover(ctx); err != nil {
				_ = conn.CloseWithError(5, "network recovery failed")
				return err
			}
			if err := networkManager.Apply(ctx); err != nil {
				_ = conn.CloseWithError(5, "network setup failed")
				return err
			}
			networkApplied = true
			activeResponse = response
			outbound = make(chan []byte, 256)
			go readTUN(ctx, tunDevice, outbound, &stats)
			log.Printf("global tunnel enabled interface=%s client_ip=%s server_ip=%s transport=%s obfs=%s", tunDevice.Name(), clientIP, serverIP, config.Transport, obfs)
		} else if !sameTunnelParameters(activeResponse, response) {
			_ = conn.CloseWithError(6, "tunnel parameters changed")
			return errors.New("server changed tunnel parameters; network configuration was restored, restart the client")
		}

		backoff = time.Second
		err = relay(ctx, conn, tunDevice, outbound, response, cipher, &stats)
		_ = conn.CloseWithError(0, "reconnecting")
		if ctx.Err() != nil {
			return nil
		}
		log.Printf("tunnel disconnected, traffic remains blocked pending reconnect: %v", err)
		if err := waitBackoff(ctx, backoff); err != nil {
			return nil
		}
	}
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

	errs := make(chan error, 2)
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
			packet, info, err := protocol.DecodeDatagram(payload, mtu, cipher)
			if err != nil || !protocol.MatchesLease(info.Destination, clientIP, client6) {
				stats.dropped.Add(1)
				continue
			}
			if err := tunDevice.WritePacket(packet); err != nil {
				errs <- err
				return
			}
			stats.recv.Add(uint64(len(packet)))
		}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errs:
		return err
	case <-conn.Context().Done():
		return context.Cause(conn.Context())
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
	jitter := time.Duration(rand.Int64N(int64(duration/2) + 1))
	timer := time.NewTimer(duration + jitter)
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
