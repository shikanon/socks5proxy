package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/shikanon/socks5proxy/internal/tunnel/protocol"
)

const (
	handshakeTimeout = 10 * time.Second
	idleTimeout      = 45 * time.Second
	keepAlivePeriod  = 15 * time.Second
)

func ClientTLS(caFile, serverName string) (*tls.Config, error) {
	var roots *x509.CertPool
	var err error
	if caFile == "" {
		roots, err = x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("load system certificate pool: %w", err)
		}
	} else {
		roots = x509.NewCertPool()
		pemData, readErr := os.ReadFile(caFile)
		if readErr != nil {
			return nil, fmt.Errorf("read CA file: %w", readErr)
		}
		if !roots.AppendCertsFromPEM(pemData) {
			return nil, errors.New("CA file contains no valid certificates")
		}
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		ServerName: serverName,
		RootCAs:    roots,
		NextProtos: []string{protocol.ALPN},
	}, nil
}

func ServerTLS(certFile, keyFile string) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load TLS certificate: %w", err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{protocol.ALPN},
	}, nil
}

func QUICConfig() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout:  handshakeTimeout,
		MaxIdleTimeout:        idleTimeout,
		KeepAlivePeriod:       keepAlivePeriod,
		Allow0RTT:             false,
		EnableDatagrams:       true,
		InitialPacketSize:     1200,
		MaxIncomingStreams:    1,
		MaxIncomingUniStreams: -1,
	}
}

func Dial(ctx context.Context, addr string, tlsConfig *tls.Config) (*quic.Conn, error) {
	conn, err := quic.DialAddr(ctx, addr, tlsConfig, QUICConfig())
	if err != nil {
		return nil, err
	}
	datagrams := conn.ConnectionState().SupportsDatagrams
	if !datagrams.Local || !datagrams.Remote {
		_ = conn.CloseWithError(1, "QUIC DATAGRAM is required")
		return nil, errors.New("peer does not support QUIC DATAGRAM")
	}
	return conn, nil
}

func Listen(addr string, tlsConfig *tls.Config) (*quic.Listener, error) {
	return quic.ListenAddr(addr, tlsConfig, QUICConfig())
}
