package socks5proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServeProxy(t *testing.T) {
	t.Run("admission_and_cancel", func(t *testing.T) {
		options, err := (ProxyOptions{MaxConnections: 1}).normalized()
		require.NoError(t, err)
		started := make(chan struct{}, 2)
		address, stop := startProxyTest(t, options, func(ctx context.Context, conn net.Conn) error {
			started <- struct{}{}
			_, err := io.Copy(io.Discard, conn)
			return err
		})
		first, err := net.Dial("tcp", address)
		require.NoError(t, err)
		defer first.Close()
		<-started
		second, err := net.Dial("tcp", address)
		require.NoError(t, err)
		defer second.Close()
		select {
		case <-started:
			t.Fatal("session admitted above limit")
		case <-time.After(50 * time.Millisecond):
		}
		first.Close()
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("released slot not reused")
		}
		stop() // Must cancel the blocked read and the blocked slot acquisition.
		second.SetReadDeadline(time.Now().Add(time.Second))
		_, err = second.Read(make([]byte, 1))
		require.Error(t, err)
		var timeout net.Error
		assert.False(t, errors.As(err, &timeout) && timeout.Timeout())
	})
	t.Run("cancel_accept", func(t *testing.T) {
		options, _ := (ProxyOptions{}).normalized()
		_, stop := startProxyTest(t, options, func(context.Context, net.Conn) error { return nil })
		stop()
	})
	t.Run("resource_errors_back_off_and_permanent_error_returns", func(t *testing.T) {
		options, _ := (ProxyOptions{}).normalized()
		listener := &errorListener{errors: []error{syscall.EMFILE, syscall.ENFILE, io.ErrUnexpectedEOF}}
		start := time.Now()
		err := serveProxy(context.Background(), listener, options, func(context.Context, net.Conn) error {
			t.Error("no connection should be accepted")
			return nil
		})
		require.ErrorIs(t, err, io.ErrUnexpectedEOF)
		assert.Empty(t, listener.errors)
		assert.GreaterOrEqual(t, time.Since(start), 15*time.Millisecond)
	})
}

type errorListener struct{ errors []error }

func (l *errorListener) Accept() (net.Conn, error) {
	err := l.errors[0]
	l.errors = l.errors[1:]
	return nil, err
}
func (*errorListener) Close() error   { return nil }
func (*errorListener) Addr() net.Addr { return &net.TCPAddr{} }

func TestRelayProxy(t *testing.T) {
	t.Run("half_close_drains_response", func(t *testing.T) {
		a, sender := tcpPair(t)
		b, receiver := tcpPair(t)
		done := make(chan error, 1)
		go func() { done <- relayProxy(context.Background(), a, b, nil, time.Second) }()
		_, err := sender.Write([]byte("request"))
		require.NoError(t, err)
		require.NoError(t, sender.CloseWrite())
		request, err := io.ReadAll(receiver)
		require.NoError(t, err)
		assert.Equal(t, "request", string(request))
		_, err = receiver.Write([]byte("complete-response"))
		require.NoError(t, err)
		require.NoError(t, receiver.CloseWrite())
		response, err := io.ReadAll(sender)
		require.NoError(t, err)
		assert.Equal(t, "complete-response", string(response))
		require.NoError(t, <-done)
	})
	for _, reason := range []string{"idle", "cancel", "read_error"} {
		t.Run(reason, func(t *testing.T) {
			a, _ := tcpPair(t)
			b, _ := tcpPair(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- relayProxy(ctx, a, b, nil, 60*time.Millisecond) }()
			if reason == "cancel" {
				cancel()
			}
			if reason == "read_error" {
				a.Close()
			}
			select {
			case err := <-done:
				require.Error(t, err)
			case <-time.After(time.Second):
				t.Fatal("relay did not release both directions")
			}
		})
	}
	t.Run("one_way_traffic_refreshes_both_endpoints", func(t *testing.T) {
		a, sender := tcpPair(t)
		b, receiver := tcpPair(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- relayProxy(ctx, a, b, nil, 300*time.Millisecond) }()
		for range 5 {
			_, err := sender.Write([]byte{42})
			require.NoError(t, err)
			packet := make([]byte, 1)
			_, err = io.ReadFull(receiver, packet)
			require.NoError(t, err)
			require.Equal(t, byte(42), packet[0])
			time.Sleep(80 * time.Millisecond)
		}
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("relay did not cancel")
		}
	})
}

func TestHandleServerSession(t *testing.T) {
	t.Run("slow_handshake_expires", func(t *testing.T) {
		conn, peer := tcpPair(t)
		options, _ := (ProxyOptions{HandshakeTimeout: 60 * time.Millisecond}).normalized()
		auth, err := CreateAuth("random", "test")
		require.NoError(t, err)
		done := make(chan error, 1)
		go func() { done <- handleServerSession(context.Background(), conn, auth, options) }()
		_, err = auth.EncodeWrite(peer, []byte{5})
		require.NoError(t, err)
		select {
		case err := <-done:
			var timeout net.Error
			require.ErrorAs(t, err, &timeout)
			require.True(t, timeout.Timeout())
		case <-time.After(time.Second):
			t.Fatal("incomplete handshake retained socket")
		}
	})
}

func TestProxyOptions(t *testing.T) {
	defaults, err := (ProxyOptions{}).normalized()
	require.NoError(t, err)
	assert.Equal(t, 256, defaults.MaxConnections)
	assert.Equal(t, 10*time.Second, defaults.DialTimeout)
	assert.Equal(t, 10*time.Second, defaults.HandshakeTimeout)
	assert.Equal(t, 5*time.Minute, defaults.IdleTimeout)
	for _, options := range []ProxyOptions{{MaxConnections: -1}, {DialTimeout: -1}, {HandshakeTimeout: -1}, {IdleTimeout: -1}} {
		_, err := options.normalized()
		require.Error(t, err)
	}
	require.Error(t, ClientContext(context.Background(), "127.0.0.1:0", "localhost:80", "random", "test", "invalid", ProxyOptions{}))
}
