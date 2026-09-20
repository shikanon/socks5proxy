package socks5proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func startProxyTest(t *testing.T, options ProxyOptions, handler func(context.Context, net.Conn) error) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveProxy(ctx, listener, options, handler) }()
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(3 * time.Second):
			t.Fatal("proxy did not shut down")
		}
	}
	t.Cleanup(stop)
	return listener.Addr().String(), stop
}

func proxyTestChain(t *testing.T, obfs, mode string, options ProxyOptions) string {
	t.Helper()
	options, err := options.normalized()
	require.NoError(t, err)
	auth, err := CreateAuth(obfs, "integration-test")
	require.NoError(t, err)
	server, _ := startProxyTest(t, options, func(ctx context.Context, conn net.Conn) error {
		return handleServerSession(ctx, conn, auth, options)
	})
	client, _ := startProxyTest(t, options, func(ctx context.Context, conn net.Conn) error {
		return handleProxySession(ctx, conn, server, auth, mode, options)
	})
	return client
}

func TestConncet(t *testing.T) {
	for _, obfs := range []string{"random", "simple"} {
		t.Run(obfs, func(t *testing.T) {
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("socks-ok")) }))
			defer target.Close()
			address := proxyTestChain(t, obfs, "socks5", ProxyOptions{})
			proxyURL, err := url.Parse("socks5h://" + address)
			require.NoError(t, err)
			transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
			response, err := client.Get(target.URL)
			require.NoError(t, err)
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			require.NoError(t, err)
			assert.Equal(t, "socks-ok", string(body))
		})
	}
}

type fragmentedBody struct{ io.Reader }

func (r fragmentedBody) Read(p []byte) (int, error) {
	if len(p) > 137 {
		p = p[:137]
	}
	return r.Reader.Read(p)
}

func TestHTTPConnect(t *testing.T) {
	address := proxyTestChain(t, "random", "http", ProxyOptions{})
	proxyURL, err := url.Parse("http://" + address)
	require.NoError(t, err)
	transport := &http.Transport{
		Proxy:                 http.ProxyURL(proxyURL),
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true}, // Local httptest certificate only.
		ExpectContinueTimeout: time.Second,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("X-Hop") != "" {
			http.Error(w, "proxy-only header leaked", 500)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		_, _ = w.Write(body)
	}))
	defer target.Close()
	for _, chunked := range []bool{false, true} {
		t.Run(fmt.Sprintf("large_post_chunked_%v", chunked), func(t *testing.T) {
			payload := bytes.Repeat([]byte("streamed-request-body\n"), 16000)
			req, err := http.NewRequest(http.MethodPost, target.URL+"/upload?x=1", fragmentedBody{bytes.NewReader(payload)})
			require.NoError(t, err)
			if !chunked {
				req.ContentLength = int64(len(payload))
			}
			req.Header.Set("Proxy-Authorization", "Basic secret")
			req.Header.Set("Connection", "X-Hop")
			req.Header.Set("X-Hop", "private")
			req.Header.Set("Expect", "100-continue")
			response, err := client.Do(req)
			require.NoError(t, err)
			defer response.Body.Close()
			assert.Equal(t, 200, response.StatusCode)
			body, err := io.ReadAll(response.Body)
			require.NoError(t, err)
			assert.Equal(t, payload, body)
		})
	}
	t.Run("https_connect", func(t *testing.T) {
		secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("tls-ok")) }))
		defer secure.Close()
		response, err := client.Get(secure.URL)
		require.NoError(t, err)
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		assert.Equal(t, "tls-ok", string(body))
	})
	for _, tc := range []struct {
		name, request string
		status        int
	}{
		{"malformed", "bad\r\n\r\n", 400},
		{"relative_url", "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n", 400},
		{"invalid_connect", "CONNECT example.test:99999 HTTP/1.1\r\nHost: example.test:99999\r\n\r\n", 400},
		{"oversized", "GET http://localhost/ HTTP/1.1\r\nX-Large: " + strings.Repeat("a", maxProxyHeader) + "\r\n\r\n", 431},
		{"zero_port", "GET http://127.0.0.1:0/ HTTP/1.1\r\nHost: 127.0.0.1:0\r\n\r\n", 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := net.Dial("tcp", address)
			require.NoError(t, err)
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			_, err = io.WriteString(conn, tc.request)
			require.NoError(t, err)
			response, err := http.ReadResponse(bufio.NewReader(conn), nil)
			require.NoError(t, err)
			defer response.Body.Close()
			assert.Equal(t, tc.status, response.StatusCode)
		})
	}
	t.Run("failed_destination_returns_502", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		target := listener.Addr().String()
		listener.Close()
		for _, request := range []string{
			fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target),
			fmt.Sprintf("GET http://%s/ HTTP/1.1\r\nHost: %s\r\n\r\n", target, target),
		} {
			conn, err := net.Dial("tcp", address)
			require.NoError(t, err)
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			_, err = io.WriteString(conn, request)
			require.NoError(t, err)
			response, err := http.ReadResponse(bufio.NewReader(conn), nil)
			require.NoError(t, err)
			assert.Equal(t, 502, response.StatusCode)
			response.Body.Close()
			conn.Close()
		}
	})
	t.Run("connect_preserves_buffered_payload_and_half_close", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer listener.Close()
		done := make(chan error, 1)
		go func() {
			target, err := listener.Accept()
			if err != nil {
				done <- err
				return
			}
			defer target.Close()
			target.SetDeadline(time.Now().Add(3 * time.Second))
			body, err := io.ReadAll(target)
			if err == nil {
				_, err = target.Write(append([]byte("reply:"), body...))
			}
			done <- err
		}()
		conn, err := net.Dial("tcp", address)
		require.NoError(t, err)
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\npipelined-body", listener.Addr(), listener.Addr())
		require.NoError(t, err)
		require.NoError(t, conn.(*net.TCPConn).CloseWrite())
		reader := bufio.NewReader(conn)
		response, err := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
		require.NoError(t, err)
		require.Equal(t, 200, response.StatusCode)
		body, err := io.ReadAll(reader)
		require.NoError(t, err)
		assert.Equal(t, "reply:pipelined-body", string(body))
		require.NoError(t, <-done)
	})
}
