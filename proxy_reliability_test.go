package socks5proxy

import (
	"bytes"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	require.NoError(t, err)
	defer listener.Close()
	peer, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	require.NoError(t, err)
	conn, err := listener.AcceptTCP()
	require.NoError(t, err)
	t.Cleanup(func() { peer.Close(); conn.Close() })
	require.NoError(t, peer.SetDeadline(time.Now().Add(2*time.Second)))
	return conn, peer
}

func TestProtocolVersionHandleHandshake(t *testing.T) {
	for _, count := range []int{1, 2, 253, 254, 255} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			packet := append([]byte{5, byte(count)}, bytes.Repeat([]byte{2}, count)...)
			packet[len(packet)-1] = 0
			response, err := (&ProtocolVersion{}).HandleHandshake(packet)
			require.NoError(t, err)
			assert.Equal(t, []byte{5, 0}, response)
		})
	}
	t.Run("unsupported_method", func(t *testing.T) {
		response, err := (&ProtocolVersion{}).HandleHandshake([]byte{5, 1, 2})
		assert.Error(t, err)
		assert.Equal(t, []byte{5, 255}, response)
	})
	for _, packet := range [][]byte{nil, {5, 0}, {4, 1, 0}, {5, 2, 0}} {
		_, err := (&ProtocolVersion{}).HandleHandshake(packet)
		assert.Error(t, err)
	}
}

func TestHandleHandshake(t *testing.T) {
	auth, err := CreateAuth("random", "test")
	require.NoError(t, err)
	for _, fragmented := range []bool{false, true} {
		t.Run(strconv.FormatBool(fragmented), func(t *testing.T) {
			packet := []byte{5, 1, 0, 5, 1, 0, 1}
			require.NoError(t, auth.Encrypt(packet))
			chunks := [][]byte{packet}
			if fragmented {
				chunks = nil
				for _, b := range packet {
					chunks = append(chunks, []byte{b})
				}
			}
			client := &preservingReadWriter{chunks: chunks}
			require.NoError(t, handleHandshake(client, auth, make([]byte, 255), &ProtocolVersion{}))
			response := client.write.Bytes()
			require.NoError(t, auth.Decrypt(response))
			assert.Equal(t, []byte{5, 0}, response)
			remaining, err := io.ReadAll(client)
			require.NoError(t, err)
			require.NoError(t, auth.Decrypt(remaining))
			assert.Equal(t, []byte{5, 1, 0, 1}, remaining)
		})
	}
}

// Unlike a packet-oriented fake, this reader preserves bytes beyond len(p).
type preservingReadWriter struct {
	chunks [][]byte
	write  bytes.Buffer
}

func (r *preservingReadWriter) Read(p []byte) (int, error) {
	if len(r.chunks) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.chunks[0])
	r.chunks[0] = r.chunks[0][n:]
	if len(r.chunks[0]) == 0 {
		r.chunks = r.chunks[1:]
	}
	return n, nil
}
func (r *preservingReadWriter) Write(p []byte) (int, error) { return r.write.Write(p) }

func TestHandleProxyRequest(t *testing.T) {
	t.Run("upstream_refusal_closes_local", func(t *testing.T) {
		reserved, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
		require.NoError(t, err)
		address := reserved.Addr().(*net.TCPAddr)
		reserved.Close()
		conn, peer := tcpPair(t)
		auth, err := CreateAuth("random", "test")
		require.NoError(t, err)
		require.Error(t, handleProxyRequest(conn, address, auth, "socks5"))
		peer.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		_, err = peer.Read(make([]byte, 1))
		assert.ErrorIs(t, err, io.EOF)
	})
}

func TestHandleClientRequest(t *testing.T) {
	t.Run("failed_target_never_returns_success", func(t *testing.T) {
		reserved, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
		require.NoError(t, err)
		port := reserved.Addr().(*net.TCPAddr).Port
		reserved.Close()
		conn, peer := tcpPair(t)
		auth, err := CreateAuth("random", "test")
		require.NoError(t, err)
		done := make(chan error, 1)
		go func() { done <- handleClientRequest(conn, auth) }()
		_, err = auth.EncodeWrite(peer, []byte{5, 1, 0})
		require.NoError(t, err)
		response, err := readEncryptedFull(peer, auth, 2)
		require.NoError(t, err)
		require.Equal(t, []byte{5, 0}, response)
		_, err = auth.EncodeWrite(peer, []byte{5, 1, 0, 1, 127, 0, 0, 1, byte(port >> 8), byte(port)})
		require.NoError(t, err)
		response, err = readEncryptedFull(peer, auth, 10)
		require.NoError(t, err)
		assert.NotZero(t, response[1])
		require.Error(t, <-done)
	})
}
