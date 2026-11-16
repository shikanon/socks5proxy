package mesh

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func fixtures(t *testing.T) (Config, Config, Config) {
	t.Helper()
	dir := t.TempDir()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	capath := filepath.Join(dir, "ca.crt")
	if e = os.WriteFile(capath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); e != nil {
		t.Fatal(e)
	}
	members := []Member{{ID: "client", IP: "100.64.0.1"}, {ID: "server", IP: "100.64.0.2", Ports: []uint16{8080, 8081}}, {ID: "control", IP: "100.64.0.3"}}
	makeConfig := func(id, ip string, serial int64) Config {
		k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), DNSNames: []string{id}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
		der, e := x509.CreateCertificate(rand.Reader, leaf, ca, &k.PublicKey, key)
		if e != nil {
			t.Fatal(e)
		}
		priv, e := x509.MarshalPKCS8PrivateKey(k)
		if e != nil {
			t.Fatal(e)
		}
		cert := filepath.Join(dir, id+".crt")
		keyfile := filepath.Join(dir, id+".key")
		if e = os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(keyfile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv}), 0600); e != nil {
			t.Fatal(e)
		}
		return Config{Version: 1, ID: id, IP: ip, Cert: cert, Key: keyfile, CA: capath, Listen: "127.0.0.1:0", Members: members}
	}
	return makeConfig("client", "100.64.0.1", 2), makeConfig("server", "100.64.0.2", 3), makeConfig("control", "100.64.0.3", 4)
}
func startNode(t *testing.T, n *Node) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- n.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		n.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("node shutdown timeout")
		}
	})
	for i := 0; i < 200; i++ {
		n.mu.Lock()
		l := n.listener
		n.mu.Unlock()
		if l != nil {
			return l.Addr().String()
		}
		select {
		case e := <-done:
			t.Fatalf("node failed: %v", e)
		default:
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("node startup timeout")
	return ""
}
func pair(t *testing.T, target string) (*Node, *Node) {
	a, b, _ := fixtures(t)
	b.Services = []Service{{Port: 8080, Target: target, Allow: []string{"client"}}}
	server, e := NewNode(b)
	if e != nil {
		t.Fatal(e)
	}
	addr := startNode(t, server)
	a.Members[1].Endpoints = []string{addr}
	client, e := NewNode(a)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { client.Close() })
	return client, server
}
func echo(t *testing.T) string {
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return l.Addr().String()
}
func TestVirtualAddressQUICStreamsAndReuse(t *testing.T) {
	client, _ := pair(t, echo(t))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for i := 0; i < 3; i++ {
		c, e := client.DialContext(ctx, "tcp", "100.64.0.2:8080")
		if e != nil {
			t.Fatal(e)
		}
		data := bytes.Repeat([]byte{byte(i + 1)}, 256*1024)
		if e = c.SetDeadline(time.Now().Add(3 * time.Second)); e != nil {
			t.Fatal(e)
		}
		written := make(chan error, 1)
		go func() { _, e := c.Write(data); written <- e }()
		got := make([]byte, len(data))
		if _, e = io.ReadFull(c, got); e != nil {
			t.Fatal(e)
		}
		if !bytes.Equal(got, data) {
			t.Fatal("stream corruption")
		}
		if e = <-written; e != nil {
			t.Fatal(e)
		}
		c.Close()
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if len(client.sessions) != 1 {
		t.Fatal("session not reused")
	}
}
func TestConcurrentStreamsIsolated(t *testing.T) {
	client, _ := pair(t, echo(t))
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			c, e := client.DialContext(ctx, "tcp", "100.64.0.2:8080")
			if e != nil {
				t.Error(e)
				return
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(3 * time.Second))
			want := bytes.Repeat([]byte{byte(i)}, 4096)
			if _, e = c.Write(want); e != nil {
				t.Error(e)
				return
			}
			got := make([]byte, len(want))
			if _, e = io.ReadFull(c, got); e != nil || !bytes.Equal(got, want) {
				t.Errorf("stream %d mismatch: %v", i, e)
			}
		}(i)
	}
	wg.Wait()
}
func TestACLRefusalAndUnknownDestination(t *testing.T) {
	client, server := pair(t, echo(t))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for _, a := range []string{"100.64.0.2:8081", "100.64.0.2:8090", "100.64.0.99:8080", "192.0.2.1:8080"} {
		if c, e := client.DialContext(ctx, "tcp", a); e == nil {
			c.Close()
			t.Fatal("unauthorized service accepted", a)
		}
	}
	server.mu.Lock()
	id := server.config.Services[0].Allow[0]
	server.mu.Unlock()
	if id != "client" {
		t.Fatal("ACL changed")
	}
	if _, e := client.DialContext(ctx, "udp", "100.64.0.2:8080"); e == nil {
		t.Fatal("UDP app accepted")
	}
}
func TestMutualTLSRejectsWrongNodeAndUntrustedCA(t *testing.T) {
	a, b, _ := fixtures(t)
	b.Services = []Service{{Port: 8080, Target: echo(t), Allow: []string{"client"}}}
	server, e := NewNode(b)
	if e != nil {
		t.Fatal(e)
	}
	addr := startNode(t, server)
	a.Members[2].Endpoints = []string{addr}
	a.Members[2].Ports = []uint16{8080}
	client, e := NewNode(a)
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, e = client.DialContext(ctx, "tcp", "100.64.0.3:8080"); e == nil {
		t.Fatal("wrong server identity accepted")
	}
	bad, _, _ := fixtures(t)
	bad.Members[1].Endpoints = []string{addr}
	other, e := NewNode(bad)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	if _, e = other.DialContext(ctx, "tcp", "100.64.0.2:8080"); e == nil {
		t.Fatal("untrusted CA accepted")
	}
}
func TestHalfCloseAllowsReverseUpload(t *testing.T) {
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	done := make(chan []byte, 1)
	go func() {
		c, e := l.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(4 * time.Second))
		_, _ = c.Write([]byte("FIN"))
		_ = c.(*net.TCPConn).CloseWrite()
		b, _ := io.ReadAll(c)
		done <- b
	}()
	client, _ := pair(t, l.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, e := client.DialContext(ctx, "tcp", "100.64.0.2:8080")
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	got, e := io.ReadAll(c)
	if e != nil || string(got) != "FIN" {
		t.Fatal("half-close damaged", string(got), e)
	}
	want := bytes.Repeat([]byte("upload"), 16384)
	if _, e = c.Write(want); e != nil {
		t.Fatal(e)
	}
	if e = c.(interface{ CloseWrite() error }).CloseWrite(); e != nil {
		t.Fatal(e)
	}
	select {
	case got = <-done:
		if !bytes.Equal(got, want) {
			t.Fatal("upload truncated")
		}
	case <-ctx.Done():
		t.Fatal("upload blocked")
	}
}
func TestDirectoryLeasesAndCandidateAuthorization(t *testing.T) {
	a, b, c := fixtures(t)
	b.Members[1].Endpoints = []string{"127.0.0.1:19001"}
	c.Members = b.Members
	a.Members = b.Members
	b.Endpoint = "127.0.0.1:19001"
	d := NewDirectory(c.Members)
	now := time.Now()
	d.now = func() time.Time { return now }
	cfg, e := ControlTLS(c)
	if e != nil {
		t.Fatal(e)
	}
	srv := httptest.NewUnstartedServer(d.Handler())
	srv.TLS = cfg
	srv.StartTLS()
	defer srv.Close()
	for _, v := range []*Config{&a, &b} {
		v.ControlURL = srv.URL
		v.ControlName = "control"
	}
	if e = Register(context.Background(), b); e != nil {
		t.Fatal(e)
	}
	rows, e := Peers(context.Background(), a)
	if e != nil || len(rows) != 1 || rows[0].ID != "server" {
		t.Fatal(rows, e)
	}
	b.Endpoint = "127.0.0.1:19002"
	if e = Register(context.Background(), b); e == nil {
		t.Fatal("unauthorized candidate registered")
	}
	now = now.Add(91 * time.Second)
	rows, e = Peers(context.Background(), a)
	if e != nil || len(rows) != 0 {
		t.Fatal("expired lease retained", e)
	}
	if r, e := http.Get(srv.URL + "/v1/peers"); e == nil {
		r.Body.Close()
		t.Fatal("unauthenticated control accepted")
	}
}
func TestConfigAndImmutableInventory(t *testing.T) {
	a, _, _ := fixtures(t)
	if e := a.Validate(); e != nil {
		t.Fatal(e)
	}
	n, e := NewNode(a)
	if e != nil {
		t.Fatal(e)
	}
	defer n.Close()
	a.Members[1].ID = "modified"
	if n.config.Members[1].ID != "server" {
		t.Fatal("inventory aliases caller")
	}
	a.IP = "10.1.1.1"
	if e = a.Validate(); e == nil {
		t.Fatal("nonoverlay IP accepted")
	}
	a, _, _ = fixtures(t)
	a.Services = []Service{{Port: 8080, Target: "169.254.169.254:80", Allow: []string{"server"}}}
	if e = a.Validate(); e == nil {
		t.Fatal("metadata export accepted")
	}
	b, _ := json.Marshal(a)
	path := filepath.Join(t.TempDir(), "bad.json")
	if e = os.WriteFile(path, append(b, []byte("{}")...), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = Load(path); e == nil {
		t.Fatal("trailing JSON accepted")
	}
}
func TestExpiredClientLeaseFailsClosed(t *testing.T) {
	client, _ := pair(t, echo(t))
	client.config.ControlURL = "https://control.invalid"
	client.expires["100.64.0.2"] = time.Now().Add(-time.Second)
	if _, e := client.DialContext(context.Background(), "tcp", "100.64.0.2:8080"); e == nil {
		t.Fatal("expired peer accepted")
	}
}
func TestTLSIdentityConfigRejectsMismatch(t *testing.T) {
	a, _, _ := fixtures(t)
	a.ID = "server"
	if _, e := TLS(a, false); e == nil {
		t.Fatal("certificate identity mismatch accepted")
	}
	a.ID = "client"
	cfg, e := TLS(a, false)
	if e != nil {
		t.Fatal(e)
	}
	if cfg.InsecureSkipVerify || cfg.MinVersion != tls.VersionTLS13 {
		t.Fatal("TLS trust weakened")
	}
}
