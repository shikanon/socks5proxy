package client

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
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
	"github.com/shikanon/socks5proxy/internal/tunnel"
	"github.com/shikanon/socks5proxy/internal/tunnel/device"
	tunnelnet "github.com/shikanon/socks5proxy/internal/tunnel/network"
	"github.com/shikanon/socks5proxy/internal/tunnel/protocol"
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
	token, err := readToken(config.TokenFile)
	if err != nil {
		return err
	}
	if len(token) < 32 {
		return errors.New("client token must contain at least 32 characters")
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
	if config.Transport != "tcp-plain" {
		tlsConfig, err = transport.ClientTLS(config.CAFile, serverName)
		if err != nil {
			return err
		}
	} else {
		log.Print("WARNING: tcp-plain has no packet encryption or integrity; obfuscation is not security")
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
		conn, response, cipher, err := connect(ctx, dialAddr, config.ClientID, token, obfs, tlsConfig, config.Transport)
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
				TUNName:      tunDevice.Name(),
				ClientIP:     clientIP,
				ServerIP:     serverIP,
				TunnelPeer:   peerIP,
				DNS:          dnsIP,
				MTU:          response.MTU,
				StateDir:     config.StateDir,
				SkipLinuxDNS: config.SkipLinuxDNS,
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
) (result transport.Conn, response protocol.Message, cipher protocol.Cipher, err error) {
	authCtx, authCancel := context.WithTimeout(ctx, 10*time.Second)
	defer authCancel()
	conn, err := transport.DialTunnel(authCtx, serverAddr, tlsConfig, kind)
	if err != nil {
		return nil, protocol.Message{}, nil, err
	}
	stop := context.AfterFunc(authCtx, func() { _ = conn.CloseWithError(1, "authentication canceled") })
	defer func() {
		stopped := stop()
		if err != nil || !stopped || authCtx.Err() != nil {
			_ = conn.CloseWithError(1, "authentication failed")
			if err == nil {
				result, err = nil, authCtx.Err()
			}
		}
	}()
	stream, err := conn.OpenControl(authCtx)
	if err != nil {
		return nil, protocol.Message{}, nil, err
	}
	deadline, _ := authCtx.Deadline()
	if err := stream.SetDeadline(deadline); err != nil {
		return nil, protocol.Message{}, nil, err
	}
	request := protocol.Message{
		Type:     protocol.TypeAuthRequest,
		Version:  protocol.Version,
		ClientID: clientID,
		Token:    token,
		Obfs:     obfs,
	}
	challenge := ""
	key := sha256.Sum256([]byte(token))
	obfsKey := token
	isTCP := kind == "tcp" || kind == "tcp-plain"
	if isTCP {
		msg, err := protocol.ReadMessage(stream)
		if err != nil {
			return nil, protocol.Message{}, nil, err
		}
		if msg.Type != protocol.TypeAuthChallenge || !protocol.ValidNonce(msg.Nonce) {
			return nil, protocol.Message{}, nil, errors.New("invalid authentication challenge")
		}
		challenge = msg.Nonce
		request.Token = ""
		request.Nonce, err = protocol.NewNonce()
		if err != nil {
			return nil, protocol.Message{}, nil, err
		}
		request.Proof = protocol.AuthProof(key, protocol.ClientProofRole, challenge, request.Nonce, request)
		obfsKey = hex.EncodeToString(key[:])
	}
	if err := protocol.WriteMessage(stream, request); err != nil {
		return nil, protocol.Message{}, nil, err
	}
	response, err = protocol.ReadMessage(stream)
	if err != nil {
		return nil, protocol.Message{}, nil, err
	}
	if response.Type == protocol.TypeError {
		return nil, protocol.Message{}, nil, errors.New(response.Error)
	}
	if response.Type != protocol.TypeAuthResponse || response.Obfs != obfs {
		return nil, protocol.Message{}, nil, errors.New("server returned invalid authentication response")
	}
	if isTCP && !protocol.VerifyAuthProof(key, protocol.ServerProofRole, challenge, request.Nonce, response) {
		return nil, protocol.Message{}, nil, errors.New("invalid server authentication proof")
	}
	cipher, err = tunnel.NewObfuscator(obfs, obfsKey)
	if err != nil {
		return nil, protocol.Message{}, nil, err
	}
	if err := stream.Close(); err != nil {
		return nil, protocol.Message{}, nil, err
	}
	return conn, response, cipher, nil
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
			if err != nil || info.Source != clientIP {
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
			if err != nil || info.Destination != clientIP {
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
		if !addr.Is4() {
			return netip.Addr{}, "", errors.New("tunnel server endpoint must resolve to IPv4")
		}
		return addr, serverName, nil
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil || len(addrs) == 0 {
		return netip.Addr{}, "", fmt.Errorf("resolve tunnel server %q: %w", host, err)
	}
	return addrs[0].Unmap(), serverName, nil
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
	return a.ClientIPv4 == b.ClientIPv4 &&
		a.ServerIPv4 == b.ServerIPv4 &&
		a.MTU == b.MTU &&
		a.DNSIPv4 == b.DNSIPv4 &&
		a.Obfs == b.Obfs
}
