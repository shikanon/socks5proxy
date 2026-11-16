package mesh

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/shikanon/socks5proxy"
)

func TestExistingHTTPProxyAcrossMesh(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("mesh-http-ok")) }))
	defer target.Close()
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	serverAddr := listener.Addr().String()
	listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- socks5proxy.ServerContext(ctx, serverAddr, "random", "test-only", socks5proxy.ProxyOptions{})
	}()
	ready := false
	for i := 0; i < 100; i++ {
		c, e := net.DialTimeout("tcp", serverAddr, 20*time.Millisecond)
		if e == nil {
			c.Close()
			ready = true
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !ready {
		t.Fatal("proxy server not ready")
	}
	client, _ := pair(t, serverAddr)
	local, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	addr := local.Addr().String()
	local.Close()
	proxyDone := make(chan error, 1)
	go func() {
		proxyDone <- socks5proxy.ClientContext(ctx, addr, "100.64.0.2:8080", "random", "test-only", "http", socks5proxy.ProxyOptions{UpstreamDialContext: client.DialContext})
	}()
	p, _ := url.Parse("http://" + addr)
	transport := &http.Transport{Proxy: http.ProxyURL(p)}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	var response *http.Response
	for i := 0; i < 100; i++ {
		response, e = httpClient.Get(target.URL)
		if e == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if e != nil {
		t.Fatal(e)
	}
	body, e := io.ReadAll(response.Body)
	response.Body.Close()
	if e != nil || string(body) != "mesh-http-ok" {
		t.Fatal(string(body), e)
	}
	cancel()
	client.Close()
	for _, done := range []chan error{proxyDone, serverDone} {
		select {
		case e = <-done:
			if e != nil {
				t.Error(e)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("shutdown blocked")
		}
	}
}
func TestExamplesAreValidatedAndNeverOverwrite(t *testing.T) {
	dir := t.TempDir()
	if e := WriteExamples(dir); e != nil {
		t.Fatal(e)
	}
	for _, id := range []string{"client", "server", "control"} {
		if _, e := Load(dir + "/" + id + ".example.json"); e != nil {
			t.Fatal(e)
		}
	}
	if e := WriteExamples(dir); e == nil {
		t.Fatal("existing example overwritten")
	}
}
func TestWaitingDialHonorsCancellation(t *testing.T) {
	client, _ := pair(t, echo(t))
	client.dialSlot <- struct{}{}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, e := client.DialContext(ctx, "tcp", "100.64.0.2:8080"); e == nil {
		t.Fatal("cancel ignored")
	}
	<-client.dialSlot
}
func TestCloseStopsAcceptedStreams(t *testing.T) {
	client, server := pair(t, echo(t))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, e := client.DialContext(ctx, "tcp", "100.64.0.2:8080")
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	if _, e = c.Write([]byte("hello")); e != nil {
		t.Fatal(e)
	}
	got := make([]byte, 5)
	if _, e = io.ReadFull(c, got); e != nil {
		t.Fatal(e)
	}
	server.Close()
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	if _, e = c.Read(got); e == nil {
		t.Fatal("closed server still accepts data")
	}
}
