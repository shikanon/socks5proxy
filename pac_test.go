package socks5proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/shikanon/socks5proxy/routing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScopeValidation(t *testing.T) {
	rules, err := routing.New([]string{"*.example.com"})
	require.NoError(t, err)
	for _, options := range []ProxyOptions{
		{Scope: "unknown"}, {Scope: "rules"}, {Rules: rules},
		{PACListen: "0.0.0.0:8090"}, {PACListen: "127.0.0.1:bad"},
	} {
		_, err := options.normalized()
		assert.Error(t, err)
	}
	for _, options := range []ProxyOptions{
		{}, {Scope: "rules", Rules: rules}, {PACListen: "[::1]:8090"},
	} {
		_, err := options.normalized()
		assert.NoError(t, err)
	}
}

func TestPACHTTP(t *testing.T) {
	rules, err := routing.New([]string{"*.example.com"})
	require.NoError(t, err)
	for _, mode := range []string{"http", "socks5"} {
		content := proxyPAC("127.0.0.1:8888", mode, ProxyOptions{Scope: "rules", Rules: rules})
		if mode == "http" {
			assert.Contains(t, content, `"PROXY 127.0.0.1:8888"`)
		} else {
			assert.Contains(t, content, `"SOCKS5 127.0.0.1:8888"`)
		}
		assert.NotContains(t, content, "; DIRECT")
		server := httptest.NewServer(pacHandler(content))
		for _, tc := range []struct {
			method, path string
			status       int
		}{
			{"GET", "/proxy.pac", 200}, {"HEAD", "/proxy.pac", 200},
			{"POST", "/proxy.pac", 405}, {"GET", "/else", 404},
		} {
			request, err := http.NewRequest(tc.method, server.URL+tc.path, nil)
			require.NoError(t, err)
			response, err := server.Client().Do(request)
			require.NoError(t, err)
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			require.NoError(t, err)
			assert.Equal(t, tc.status, response.StatusCode)
			if tc.method == "GET" && tc.status == 200 {
				assert.Equal(t, content, string(body))
				assert.Equal(t, "application/x-ns-proxy-autoconfig", response.Header.Get("Content-Type"))
				assert.Equal(t, "no-store", response.Header.Get("Cache-Control"))
			}
			if tc.method == "HEAD" {
				assert.Empty(t, body)
			}
		}
		server.Close()
	}
}

func TestPACListenerLifecycle(t *testing.T) {
	// Occupied PAC port must release the already-created application listener.
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()
	options, err := (ProxyOptions{PACListen: occupied.Addr().String()}).normalized()
	require.NoError(t, err)
	auth, err := CreateAuth("random", "test")
	require.NoError(t, err)
	require.Error(t, serveClientProxy(context.Background(), listener, "127.0.0.1:1", auth, "http", options))
	rebound, err := net.Listen("tcp", address)
	require.NoError(t, err)
	rebound.Close()
	pacAddress := occupied.Addr().String()
	occupied.Close()
	listener, err = net.Listen("tcp", address)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveClientProxy(ctx, listener, "127.0.0.1:1", auth, "http", options) }()
	require.Eventually(t, func() bool {
		conn, err := net.DialTimeout("tcp", pacAddress, 50*time.Millisecond)
		if err != nil {
			return false
		}
		conn.Close()
		return true
	}, time.Second, 10*time.Millisecond)
	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("PAC did not stop on cancellation")
	}
	for _, address := range []string{address, pacAddress} {
		rebound, err := net.Listen("tcp", address)
		require.NoError(t, err)
		rebound.Close()
	}
}
