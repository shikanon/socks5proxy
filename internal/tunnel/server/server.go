package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"runtime"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/shikanon/socks5proxy/internal/tunnel"
	"github.com/shikanon/socks5proxy/internal/tunnel/device"
	tunnelnet "github.com/shikanon/socks5proxy/internal/tunnel/network"
	"github.com/shikanon/socks5proxy/internal/tunnel/protocol"
	"github.com/shikanon/socks5proxy/internal/tunnel/transport"
)

const sessionQueueSize = 256

type Server struct {
	config   tunnel.ServerConfig
	device   device.Device
	pool     *AddressPool
	tokens   *TokenStore
	sessions *sessionTable
}

func Run(ctx context.Context, config tunnel.ServerConfig) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("tunnel server requires Linux, got %s", runtime.GOOS)
	}
	if err := config.SetDefaults(); err != nil {
		return err
	}
	if err := config.Validate(); err != nil {
		return err
	}
	tokens, err := LoadTokenStore(config.TokenFile)
	if err != nil {
		return err
	}
	pool, err := NewAddressPool(config.TunnelCIDR)
	if err != nil {
		return err
	}
	if err := pool.Reserve(tokens.ClientIDs()); err != nil {
		return err
	}
	tlsConfig, err := transport.ServerTLS(config.CertFile, config.KeyFile)
	if err != nil {
		return err
	}
	tunDevice, err := device.Create(config.TUNName, config.MTU)
	if err != nil {
		return err
	}
	defer tunDevice.Close()

	prefix, _ := netip.ParsePrefix(config.TunnelCIDR)
	networkManager, err := tunnelnet.NewServerManager(tunnelnet.ServerOptions{
		TUNName:           tunDevice.Name(),
		TunnelPrefix:      prefix.Masked(),
		ServerIP:          pool.Server(),
		MTU:               config.MTU,
		OutboundInterface: config.OutboundInterface,
		ManageNetwork:     config.ManageNetwork,
		StateDir:          config.StateDir,
	}, nil)
	if err != nil {
		return err
	}
	if err := networkManager.Apply(ctx); err != nil {
		return err
	}
	defer func() {
		restoreCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := networkManager.Restore(restoreCtx); err != nil {
			log.Printf("tunnel server network restore failed: %v", err)
		}
	}()

	listener, err := transport.Listen(config.ListenAddr, tlsConfig)
	if err != nil {
		return err
	}
	defer listener.Close()

	server := &Server{
		config:   config,
		device:   tunDevice,
		pool:     pool,
		tokens:   tokens,
		sessions: newSessionTable(),
	}
	go func() {
		<-ctx.Done()
		server.sessions.closeAll()
		_ = listener.Close()
	}()
	go server.downlink(ctx)

	log.Printf("tunnel server listening on %s with TUN %s", config.ListenAddr, tunDevice.Name())
	for {
		conn, err := listener.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go server.handleConnection(ctx, conn)
	}
}

func (s *Server) handleConnection(parent context.Context, conn *quic.Conn) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	defer conn.CloseWithError(0, "session closed")
	datagrams := conn.ConnectionState().SupportsDatagrams
	if !datagrams.Local || !datagrams.Remote {
		_ = conn.CloseWithError(1, "QUIC DATAGRAM is required")
		return
	}

	authCtx, authCancel := context.WithTimeout(ctx, 10*time.Second)
	stream, err := conn.AcceptStream(authCtx)
	authCancel()
	if err != nil {
		return
	}
	request, err := protocol.ReadMessage(stream)
	if err != nil || request.Type != protocol.TypeAuthRequest {
		s.reject(stream)
		return
	}
	obfs, err := tunnel.NormalizeObfs(request.Obfs)
	if err != nil || !s.config.ObfsAllow[obfs] || len(request.Token) < 32 || !s.tokens.Authenticate(request.ClientID, request.Token) {
		s.reject(stream)
		return
	}
	cipher, err := tunnel.NewObfuscator(obfs, request.Token)
	if err != nil {
		s.reject(stream)
		return
	}
	clientAddr, err := s.pool.Acquire(request.ClientID)
	if err != nil {
		_ = protocol.WriteMessage(stream, protocol.Message{Type: protocol.TypeError, Version: protocol.Version, Error: "server unavailable"})
		return
	}
	current := &session{
		id:       newSessionID(),
		clientID: request.ClientID,
		addr:     clientAddr,
		obfs:     obfs,
		cipher:   cipher,
		conn:     conn,
		send:     make(chan []byte, sessionQueueSize),
		started:  time.Now(),
	}
	if err := protocol.WriteMessage(stream, protocol.Message{
		Type:       protocol.TypeAuthResponse,
		Version:    protocol.Version,
		SessionID:  current.id,
		ClientIPv4: clientAddr.String(),
		ServerIPv4: s.pool.Server().String(),
		MTU:        s.config.MTU,
		DNSIPv4:    s.config.DNS,
		Obfs:       obfs,
	}); err != nil {
		return
	}
	_ = stream.Close()

	previous := s.sessions.register(current)
	if previous != nil {
		_ = previous.conn.CloseWithError(2, "replaced by a new session")
	}
	defer s.sessions.remove(current)
	defer s.logSession(current)
	go s.sendLoop(ctx, current)

	for {
		payload, err := conn.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		packet, info, err := protocol.DecodeDatagram(payload, s.config.MTU, current.cipher)
		if err != nil || info.Source != current.addr {
			current.dropped.Add(1)
			continue
		}
		if err := s.device.WritePacket(packet); err != nil {
			return
		}
		current.recvBytes.Add(uint64(len(packet)))
	}
}

func (s *Server) reject(stream *quic.Stream) {
	_ = protocol.WriteMessage(stream, protocol.Message{
		Type:    protocol.TypeError,
		Version: protocol.Version,
		Error:   "authentication failed",
	})
	_ = stream.Close()
}

func (s *Server) sendLoop(ctx context.Context, current *session) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-current.conn.Context().Done():
			return
		case payload := <-current.send:
			if err := current.conn.SendDatagram(payload); err != nil {
				_ = current.conn.CloseWithError(3, "datagram send failed")
				return
			}
			current.sentBytes.Add(uint64(len(payload) - 2))
		}
	}
}

func (s *Server) downlink(ctx context.Context) {
	for {
		packet, err := s.device.ReadPacket()
		if err != nil {
			if ctx.Err() == nil && !errors.Is(err, context.Canceled) {
				log.Printf("tunnel server TUN read failed: %v", err)
			}
			return
		}
		info, err := protocol.ValidateIPv4(packet, s.config.MTU)
		if err != nil {
			continue
		}
		current := s.sessions.byAddress(info.Destination)
		if current == nil {
			continue
		}
		payload, _, err := protocol.EncodeDatagram(packet, s.config.MTU, current.cipher)
		if err != nil {
			current.dropped.Add(1)
			continue
		}
		select {
		case current.send <- payload:
		default:
			current.dropped.Add(1)
		}
	}
}

func (s *Server) logSession(current *session) {
	log.Printf(
		"tunnel session closed session_id=%s client_id=%s obfs=%s duration=%s rx_bytes=%d tx_bytes=%d dropped=%d",
		current.id,
		current.clientID,
		current.obfs,
		time.Since(current.started).Round(time.Second),
		current.recvBytes.Load(),
		current.sentBytes.Load(),
		current.dropped.Load(),
	)
}

func newSessionID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return strings.ReplaceAll(time.Now().UTC().Format(time.RFC3339Nano), ":", "")
	}
	return hex.EncodeToString(value[:])
}
