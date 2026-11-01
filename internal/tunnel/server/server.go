package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/shikanon/socks5proxy/internal/keytable"
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
	table    *keytable.Table
	sessions *sessionTable
}

func Run(ctx context.Context, config tunnel.ServerConfig) error {
	ctx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	if runtime.GOOS != "linux" {
		return fmt.Errorf("tunnel server requires Linux, got %s", runtime.GOOS)
	}
	if err := config.SetDefaults(); err != nil {
		return err
	}
	if err := config.Validate(); err != nil {
		return err
	}
	if config.Transport == "quic" && !config.IPv6 && config.MTU > tunnel.DefaultMTU {
		log.Printf("limiting tunnel MTU from %d to %d for QUIC datagram capacity", config.MTU, tunnel.DefaultMTU)
		config.MTU = tunnel.DefaultMTU
	}
	var table *keytable.Table
	var tokens *TokenStore
	var err error
	if config.Transport == "tcp-table" {
		var created bool
		table, created, err = keytable.LoadOrCreate(config.TableFile, config.TableTokenLength)
		if err == nil {
			tokens = &TokenStore{hashes: map[string][sha256.Size]byte{
				config.TableClientID: sha256.Sum256([]byte(table.Credential())),
			}}
			log.Printf("token table ready path=%s created=%t client_id=%s", config.TableFile, created, config.TableClientID)
		}
	} else {
		tokens, err = LoadTokenStore(config.TokenFile)
	}
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
	var tlsConfig *tls.Config
	if config.Transport != "tcp-plain" && config.Transport != "tcp-table" {
		tlsConfig, err = transport.ServerTLS(config.CertFile, config.KeyFile)
		if err != nil {
			return err
		}
	} else if config.Transport == "tcp-plain" {
		log.Print("WARNING: tcp-plain has no packet encryption or integrity; obfuscation is not security")
	} else {
		log.Print("tcp-table uses a learning-only daily substitution table; no TLS or packet integrity")
	}
	tunDevice, err := device.Create(config.TUNName, config.MTU)
	if err != nil {
		return err
	}
	defer tunDevice.Close()

	prefix, _ := netip.ParsePrefix(config.TunnelCIDR)
	var prefix6 netip.Prefix
	var server6 netip.Addr
	if config.IPv6 {
		prefix6, _ = netip.ParsePrefix(config.TunnelCIDR6)
		server6 = pool.IPv6(prefix6, pool.Server())
	}
	networkManager, err := tunnelnet.NewServerManager(tunnelnet.ServerOptions{
		TUNName:           tunDevice.Name(),
		TunnelPrefix:      prefix.Masked(),
		ServerIP:          pool.Server(),
		TunnelPrefix6:     prefix6,
		ServerIPv6:        server6,
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

	listener, err := transport.ListenTunnel(config.ListenAddr, tlsConfig, config.Transport)
	if err != nil {
		return err
	}
	defer listener.Close()

	server := &Server{
		config:   config,
		device:   tunDevice,
		pool:     pool,
		tokens:   tokens,
		table:    table,
		sessions: newSessionTable(),
	}
	var handlers sync.WaitGroup
	defer func() {
		cancelRun()
		server.sessions.closeAll()
		_ = listener.Close()
		handlers.Wait()
	}()
	go func() {
		<-ctx.Done()
		server.sessions.closeAll()
		_ = listener.Close()
	}()
	go server.downlink(ctx)

	log.Printf("tunnel server listening on %s transport=%s with TUN %s", config.ListenAddr, config.Transport, tunDevice.Name())
	for {
		conn, err := listener.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		handlers.Add(1)
		go func() {
			defer handlers.Done()
			server.handleConnection(ctx, conn)
		}()
	}
}

func (s *Server) handleConnection(parent context.Context, conn transport.Conn) {
	if s.config.Transport == "tcp-table" && s.table != nil {
		conn = transport.WithTable(conn, s.table)
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	defer conn.CloseWithError(0, "session closed")
	authConn := conn
	stopParent := context.AfterFunc(ctx, func() { _ = authConn.CloseWithError(0, "server context canceled") })
	defer stopParent()

	authCtx, authCancel := context.WithTimeout(ctx, 10*time.Second)
	defer authCancel()
	stopAuth := context.AfterFunc(authCtx, func() { _ = authConn.CloseWithError(1, "authentication timed out") })
	defer stopAuth()
	stream, err := conn.AcceptControl(authCtx)
	if err != nil {
		return
	}
	deadline, _ := authCtx.Deadline()
	if stream.SetDeadline(deadline) != nil {
		return
	}
	isTCP := s.config.Transport == "tcp" || s.config.Transport == "tcp-plain" || s.config.Transport == "tcp-table"
	challenge := ""
	if isTCP {
		challenge, err = protocol.NewNonce()
		if err != nil || protocol.WriteMessage(stream, protocol.Message{
			Type: protocol.TypeAuthChallenge, Version: protocol.Version, Nonce: challenge,
		}) != nil {
			return
		}
	}
	request, err := protocol.ReadMessage(stream)
	if err != nil || request.Type != protocol.TypeAuthRequest {
		s.reject(stream)
		return
	}
	obfs, err := tunnel.NormalizeObfs(request.Obfs)
	if err != nil || !s.config.ObfsAllow[obfs] || (s.config.Transport == "tcp-table" && obfs != "none") {
		s.reject(stream)
		return
	}
	obfsKey := request.Token
	var proofKey [sha256.Size]byte
	authenticated := false
	if isTCP {
		proofKey, authenticated = s.tokens.AuthenticateProof(challenge, request)
		obfsKey = hex.EncodeToString(proofKey[:])
	} else {
		authenticated = len(request.Token) >= 32 && s.tokens.Authenticate(request.ClientID, request.Token)
	}
	if !authenticated {
		s.reject(stream)
		return
	}
	if request.IPv6 && !s.config.IPv6 {
		_ = protocol.WriteMessage(stream, protocol.Message{Type: protocol.TypeError, Version: protocol.Version, Error: "IPv6 tunnel is not enabled on the server"})
		return
	}
	if s.config.Transport == "tcp-table" && s.table == nil {
		s.reject(stream)
		return
	}
	cipher, err := tunnel.NewObfuscator(obfs, obfsKey)
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
		mtu:      s.config.MTU,
		obfs:     obfs,
		cipher:   cipher,
		conn:     conn,
		send:     make(chan []byte, sessionQueueSize),
		started:  time.Now(),
	}
	response := protocol.Message{
		Type:       protocol.TypeAuthResponse,
		Version:    protocol.Version,
		SessionID:  current.id,
		ClientIPv4: clientAddr.String(),
		ServerIPv4: s.pool.Server().String(),
		MTU:        s.config.MTU,
		DNSIPv4:    s.config.DNS,
		Obfs:       obfs,
	}
	if request.IPv6 {
		prefix6, _ := netip.ParsePrefix(s.config.TunnelCIDR6)
		current.addr6 = s.pool.IPv6(prefix6, clientAddr)
		response.IPv6 = true
		response.ClientIPv6 = current.addr6.String()
		response.ServerIPv6 = s.pool.IPv6(prefix6, s.pool.Server()).String()
		response.DNSIPv6 = s.config.DNSIPv6
	} else if s.config.Transport == "quic" && current.mtu > tunnel.DefaultMTU {
		current.mtu = tunnel.DefaultMTU
		response.MTU = current.mtu
	}
	if isTCP {
		response.Proof = protocol.AuthProof(proofKey, protocol.ServerProofRole, challenge, request.Nonce, response)
	}
	if err := protocol.WriteMessage(stream, response); err != nil {
		return
	}
	if stream.Close() != nil {
		return
	}
	if !stopAuth() || authCtx.Err() != nil {
		return
	}
	authCancel()
	if request.IPv6 && !isTCP {
		conn = transport.WithFragmentation(conn)
		current.conn = conn
	}

	previous := s.sessions.register(current)
	if previous != nil {
		_ = previous.conn.CloseWithError(2, "replaced by a new session")
	}
	defer s.sessions.remove(current)
	defer s.logSession(current)
	sendDone := make(chan struct{})
	go func() {
		defer close(sendDone)
		s.sendLoop(ctx, current)
	}()
	defer func() {
		cancel()
		_ = conn.CloseWithError(0, "session closed")
		<-sendDone
	}()

	for {
		payload, err := conn.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		packet, info, err := protocol.DecodeDatagram(payload, current.mtu, current.cipher)
		if err != nil || !protocol.MatchesLease(info.Source, current.addr, current.addr6) {
			current.dropped.Add(1)
			continue
		}
		if err := s.device.WritePacket(packet); err != nil {
			return
		}
		current.recvBytes.Add(uint64(len(packet)))
	}
}

func (s *Server) reject(stream transport.ControlStream) {
	_ = protocol.WriteMessage(stream, protocol.Message{
		Type:    protocol.TypeError,
		Version: protocol.Version,
		Error:   "authentication failed",
	})
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
				var tooLarge *quic.DatagramTooLargeError
				if errors.As(err, &tooLarge) {
					current.dropped.Add(1)
					continue
				}
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
		info, err := protocol.ValidatePacket(packet, s.config.MTU)
		if err != nil {
			continue
		}
		current := s.sessions.byAddress(info.Destination)
		if current == nil {
			continue
		}
		payload, _, err := protocol.EncodeDatagram(packet, current.mtu, current.cipher)
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
