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
	"sync/atomic"
	"testing"
	"time"

	"github.com/shikanon/socks5proxy/routing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func selectiveClient(t *testing.T, remote, mode, pattern string) string {
	t.Helper()
	rules, err := routing.New([]string{pattern})
	require.NoError(t, err)
	options, err := (ProxyOptions{Scope: "rules", Rules: rules}).normalized()
	require.NoError(t, err)
	auth, err := CreateAuth("random", "integration-test")
	require.NoError(t, err)
	address, _ := startProxyTest(t, options, func(ctx context.Context, conn net.Conn) error {
		return handleProxySession(ctx, conn, remote, auth, mode, options)
	})
	return address
}

func selectiveHTTPClient(t *testing.T, address, mode string) *http.Client {
	t.Helper()
	scheme := "http"
	if mode == "socks5" {
		scheme = "socks5h"
	}
	proxyURL, err := url.Parse(scheme + "://" + address)
	require.NoError(t, err)
	transport := &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // Local httptest only.
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 3 * time.Second}
}

func TestSelectiveDestinationRoutes(t *testing.T) {
	for _, mode := range []string{"http", "socks5"} {
		for _, secure := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/tls_%v", mode, secure), func(t *testing.T) {
				options, err := (ProxyOptions{}).normalized()
				require.NoError(t, err)
				auth, err := CreateAuth("random", "integration-test")
				require.NoError(t, err)
				var upstreamConnections atomic.Int32
				remote, _ := startProxyTest(t, options, func(ctx context.Context, conn net.Conn) error {
					upstreamConnections.Add(1)
					return handleServerSession(ctx, conn, auth, options)
				})
				handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					body, err := io.ReadAll(r.Body)
					if err != nil {
						http.Error(w, err.Error(), 500)
						return
					}
					_, _ = w.Write(body)
				})
				var target *httptest.Server
				if secure {
					target = httptest.NewTLSServer(handler)
				} else {
					target = httptest.NewServer(handler)
				}
				defer target.Close()
				address := selectiveClient(t, remote, mode, "local*")
				client := selectiveHTTPClient(t, address, mode)
				for _, tc := range []struct {
					target string
					count  int32
				}{
					{target.URL, 0}, // Literal IP misses: no connection to remote.
					{strings.Replace(target.URL, "127.0.0.1", "localhost", 1), 1},
				} {
					payload := strings.Repeat("routed-body", 10000)
					response, err := client.Post(tc.target, "text/plain", strings.NewReader(payload))
					require.NoError(t, err)
					body, err := io.ReadAll(response.Body)
					response.Body.Close()
					require.NoError(t, err)
					assert.True(t, bytes.Equal([]byte(payload), body), "body mismatch: sent %d received %d", len(payload), len(body))
					assert.Equal(t, tc.count, upstreamConnections.Load())
				}
			})
		}
	}
}

func TestSelectiveRemoteFailureDoesNotChangeRoute(t *testing.T) {
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	remote := closed.Addr().String()
	require.NoError(t, closed.Close())
	for _, mode := range []string{"http", "socks5"} {
		t.Run(mode, func(t *testing.T) {
			var visits atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				visits.Add(1)
				_, _ = w.Write([]byte("direct-ok"))
			}))
			defer target.Close()
			address := selectiveClient(t, remote, mode, "*.localhost")
			client := selectiveHTTPClient(t, address, mode)
			response, err := client.Get(target.URL)
			require.NoError(t, err)
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			require.NoError(t, err)
			assert.Equal(t, "direct-ok", string(body))
			response, err = client.Get(strings.Replace(target.URL, "127.0.0.1", "localhost", 1))
			if mode == "http" {
				require.NoError(t, err)
				assert.Equal(t, 502, response.StatusCode)
				response.Body.Close()
			} else {
				require.Error(t, err)
			}
			assert.Equal(t, int32(1), visits.Load(), "matched request must not reach origin directly")
		})
	}
}

func TestInvalidLocalSOCKSDoesNotDialUpstream(t *testing.T) {
	options, err := (ProxyOptions{}).normalized()
	require.NoError(t, err)
	var count atomic.Int32
	remote, _ := startProxyTest(t, options, func(ctx context.Context, conn net.Conn) error {
		count.Add(1)
		return nil
	})
	address := selectiveClient(t, remote, "socks5", "*")
	for _, greeting := range [][]byte{{5, 1, 2}, {4, 1, 0}} {
		conn, err := net.Dial("tcp", address)
		require.NoError(t, err)
		conn.SetDeadline(time.Now().Add(time.Second))
		_, err = conn.Write(greeting)
		require.NoError(t, err)
		_, _ = io.ReadAll(conn)
		conn.Close()
	}
	assert.Zero(t, count.Load())
}

func TestDirectConnectBufferedPayloadHalfClose(t *testing.T) {
	origin, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer origin.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := origin.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		body, err := io.ReadAll(conn)
		if err == nil {
			_, err = conn.Write(append([]byte("reply:"), body...))
		}
		done <- err
	}()
	address := selectiveClient(t, "127.0.0.1:1", "http", "else.test")
	conn, err := net.Dial("tcp", address)
	require.NoError(t, err)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\nbuffered", origin.Addr(), origin.Addr())
	require.NoError(t, err)
	require.NoError(t, conn.(*net.TCPConn).CloseWrite())
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
	require.NoError(t, err)
	require.Equal(t, 200, response.StatusCode)
	body, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, "reply:buffered", string(body))
	require.NoError(t, <-done)
}
