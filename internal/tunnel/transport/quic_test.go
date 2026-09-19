package transport

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/shikanon/socks5proxy/internal/tunnel"
)

func TestMinimumPathCarriesFullTunnelMTU(t *testing.T) {
	certFile, keyFile, caFile := writeTestCertificates(t)
	serverTLS, err := ServerTLS(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	config := QUICConfig()
	if config.InitialPacketSize != 1200 {
		t.Fatal("initial packets must fit the minimum QUIC path")
	}
	config.DisablePathMTUDiscovery = true
	listener, err := quic.ListenAddr("127.0.0.1:0", serverTLS, config)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	clientTLS, err := ClientTLS(caFile, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := quic.DialAddr(ctx, listener.Addr().String(), clientTLS, config)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseWithError(0, "test complete")
	server, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer server.CloseWithError(0, "test complete")
	payload := bytes.Repeat([]byte{0xa5}, tunnel.DefaultMTU+2)
	for _, pair := range [][2]*quic.Conn{{client, server}, {server, client}} {
		if err := pair[0].SendDatagram(payload); err != nil {
			t.Fatalf("full-MTU send on minimum QUIC path: %v", err)
		}
		got, err := pair[1].ReceiveDatagram(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatal("full-MTU payload changed in transit")
		}
	}
}

func TestQUICHandshakeUsesTLS13AndDatagrams(t *testing.T) {
	certFile, keyFile, caFile := writeTestCertificates(t)
	serverTLS, err := ServerTLS(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := Listen("127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	clientTLS, err := ClientTLS(caFile, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := Dial(ctx, listener.Addr().String(), clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	if got := conn.ConnectionState().TLS.Version; got != tls.VersionTLS13 {
		t.Fatalf("unexpected TLS version %#x", got)
	}
	datagrams := conn.ConnectionState().SupportsDatagrams
	if !datagrams.Local || !datagrams.Remote {
		t.Fatal("QUIC DATAGRAM support was not negotiated")
	}
	_ = conn.CloseWithError(0, "test complete")
}

func TestQUICHandshakeRejectsWrongServerName(t *testing.T) {
	certFile, keyFile, caFile := writeTestCertificates(t)
	serverTLS, err := ServerTLS(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := Listen("127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	clientTLS, err := ClientTLS(caFile, "not-localhost")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := Dial(ctx, listener.Addr().String(), clientTLS); err == nil {
		t.Fatal("expected certificate name validation failure")
	}
}

func TestQUICHandshakeRejectsUntrustedCertificate(t *testing.T) {
	certFile, keyFile, _ := writeTestCertificates(t)
	serverTLS, err := ServerTLS(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := Listen("127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	clientTLS, err := ClientTLS("", "localhost")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := Dial(ctx, listener.Addr().String(), clientTLS); err == nil {
		t.Fatal("expected untrusted certificate failure")
	}
}

func TestQUICHandshakeRejectsWrongALPN(t *testing.T) {
	certFile, keyFile, caFile := writeTestCertificates(t)
	serverTLS, err := ServerTLS(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	serverTLS.NextProtos = []string{"wrong-protocol"}
	listener, err := quic.ListenAddr("127.0.0.1:0", serverTLS, QUICConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	clientTLS, err := ClientTLS(caFile, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := Dial(ctx, listener.Addr().String(), clientTLS); err == nil {
		t.Fatal("expected ALPN negotiation failure")
	}
}

func TestQUICHandshakeRequiresDatagramSupport(t *testing.T) {
	certFile, keyFile, caFile := writeTestCertificates(t)
	serverTLS, err := ServerTLS(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	serverQUIC := QUICConfig()
	serverQUIC.EnableDatagrams = false
	listener, err := quic.ListenAddr("127.0.0.1:0", serverTLS, serverQUIC)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	clientTLS, err := ClientTLS(caFile, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := Dial(ctx, listener.Addr().String(), clientTLS); err == nil {
		t.Fatal("expected QUIC DATAGRAM negotiation failure")
	}
}

func writeTestCertificates(t *testing.T) (string, string, string) {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caTemplate, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	certFile := filepath.Join(dir, "server.crt")
	keyFile := filepath.Join(dir, "server.key")
	caFile := filepath.Join(dir, "ca.crt")
	writePEM(t, certFile, "CERTIFICATE", serverDER, 0o600)
	writePEM(t, keyFile, "PRIVATE KEY", keyDER, 0o600)
	writePEM(t, caFile, "CERTIFICATE", caDER, 0o600)
	return certFile, keyFile, caFile
}

func writePEM(t *testing.T, path, blockType string, der []byte, mode os.FileMode) {
	t.Helper()
	data := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}
