package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/shikanon/socks5proxy/internal/tunnel/protocol"
)

type limitedWriter struct {
	bytes.Buffer
	limit int
	err   error
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if len(p) > w.limit {
		p = p[:w.limit]
	}
	return w.Buffer.Write(p)
}

func TestWriteFrame(t *testing.T) {
	for _, size := range []int{0, 1, maxTCPDatagram, maxTCPDatagram + 1} {
		payload := bytes.Repeat([]byte{0xa5}, size)
		w := &limitedWriter{limit: 1}
		err := writeFrame(w, payload)
		if size > maxTCPDatagram {
			if err == nil || w.Len() != 0 {
				t.Fatal("oversized packet written")
			}
			continue
		}
		if err != nil || int(binary.BigEndian.Uint16(w.Bytes())) != size || !bytes.Equal(w.Bytes()[2:], payload) {
			t.Fatal("short write changed frame", size, err)
		}
	}
	for _, w := range []*limitedWriter{{limit: 0}, {limit: 3, err: io.ErrClosedPipe}} {
		if writeFrame(w, []byte("abc")) == nil {
			t.Fatal("failed writer accepted")
		}
	}
}

func pipeConn(t *testing.T) (*tcpConn, net.Conn) {
	t.Helper()
	local, peer := net.Pipe()
	c := newTCPConn(local, local)
	t.Cleanup(func() { _ = c.CloseWithError(0, "test"); _ = peer.Close() })
	if err := c.startData(); err != nil {
		t.Fatal(err)
	}
	return c, peer
}

func TestTCPReceiveFrames(t *testing.T) {
	t.Run("segmentation_coalescing_and_heartbeats", func(t *testing.T) {
		c, peer := pipeConn(t)
		payloads := [][]byte{[]byte("first"), bytes.Repeat([]byte{1}, maxTCPDatagram)}
		go func() {
			var wire bytes.Buffer
			_ = writeFrame(&wire, nil)
			_ = writeFrame(&wire, payloads[0])
			_ = writeFrame(&wire, nil)
			_ = writeFrame(&wire, payloads[1])
			data := wire.Bytes()
			_, _ = peer.Write(data[:1])
			_, _ = peer.Write(data[1:4])
			_, _ = peer.Write(data[4:])
		}()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		for _, want := range payloads {
			got, err := c.ReceiveDatagram(ctx)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatal("framing changed packet", err)
			}
		}
	})
	for _, tc := range []struct {
		name string
		wire []byte
	}{
		{"partial_header", []byte{0}},
		{"partial_payload", []byte{0, 5, 1, 2}},
		{"oversized", []byte{0xff, 0xff}},
		{"eof", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, peer := pipeConn(t)
			go func() { _, _ = peer.Write(tc.wire); _ = peer.Close() }()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if _, err := c.ReceiveDatagram(ctx); err == nil {
				t.Fatal("invalid frame accepted")
			}
			select {
			case <-c.Context().Done():
			default:
				t.Fatal("invalid frame did not close connection")
			}
		})
	}
	t.Run("cancel_blocked_receive", func(t *testing.T) {
		c, _ := pipeConn(t)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { _, err := c.ReceiveDatagram(ctx); done <- err }()
		cancel()
		select {
		case err := <-done:
			if err == nil || c.Context().Err() == nil {
				t.Fatal("canceled receive succeeded")
			}
		case <-time.After(time.Second):
			t.Fatal("receive did not cancel")
		}
	})
}

func TestTCPConcurrentWrites(t *testing.T) {
	sender, peer := pipeConn(t)
	receiver := newTCPConn(peer, peer)
	t.Cleanup(func() { _ = receiver.CloseWithError(0, "test") })
	_ = receiver.startData()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	const count = 80
	var writers sync.WaitGroup
	errorsCh := make(chan error, count*2)
	for n := 0; n < count; n++ {
		writers.Add(2)
		go func(n int) {
			defer writers.Done()
			errorsCh <- sender.SendDatagram([]byte{byte(n), 0xa5})
		}(n)
		go func() {
			defer writers.Done()
			errorsCh <- sender.sendFrame(nil)
		}()
	}
	seen := map[byte]bool{}
	// Keep reading to drain any trailing heartbeat while writers finish.
	readDone := make(chan error, 1)
	go func() {
		for len(seen) < count {
			got, err := receiver.ReceiveDatagram(ctx)
			if err != nil {
				readDone <- err
				return
			}
			if len(got) != 2 || got[1] != 0xa5 || seen[got[0]] {
				readDone <- errors.New("concurrent writes corrupted frame")
				return
			}
			seen[got[0]] = true
		}
		readDone <- nil
		_, _ = receiver.ReceiveDatagram(ctx)
	}()
	if err := <-readDone; err != nil {
		t.Fatal(err)
	}
	writers.Wait()
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	cancel()
	if sender.SendDatagram(nil) == nil || sender.SendDatagram(make([]byte, maxTCPDatagram+1)) == nil {
		t.Fatal("reserved or oversized datagram accepted")
	}
}

func TestTunnelDispatchRoundTrip(t *testing.T) {
	cert, key, ca := writeTestCertificates(t)
	serverTLS, _ := ServerTLS(cert, key)
	clientTLS, _ := ClientTLS(ca, "localhost")
	for _, kind := range []string{"quic", "tcp", "tcp-plain"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			l, err := ListenTunnel("127.0.0.1:0", serverTLS, kind)
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			done := make(chan error, 1)
			ready := make(chan struct{})
			go func() {
				c, err := l.Accept(ctx)
				if err != nil {
					done <- err
					return
				}
				defer c.CloseWithError(0, "test")
				stream, err := c.AcceptControl(ctx)
				if err == nil {
					_, err = protocol.ReadMessage(stream)
				}
				if err == nil {
					err = protocol.WriteMessage(stream, protocol.Message{Type: protocol.TypeAuthResponse, Version: protocol.Version})
				}
				if err == nil {
					err = stream.Close()
				}
				close(ready)
				var payload []byte
				if err == nil {
					payload, err = c.ReceiveDatagram(ctx)
				}
				if err == nil {
					err = c.SendDatagram(payload)
				}
				done <- err
				<-ctx.Done()
			}()
			c, err := DialTunnel(ctx, l.Addr().String(), clientTLS, kind)
			if err != nil {
				t.Fatal(err)
			}
			defer c.CloseWithError(0, "test")
			if kind == "tcp" && c.(*tcpConn).wire.(*tls.Conn).ConnectionState().Version != tls.VersionTLS13 {
				t.Fatal("TCP TLS did not use TLS 1.3")
			}
			stream, err := c.OpenControl(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := protocol.WriteMessage(stream, protocol.Message{Type: protocol.TypeAuthRequest, Version: protocol.Version}); err != nil {
				t.Fatal(err)
			}
			if _, err := protocol.ReadMessage(stream); err != nil {
				t.Fatal(err)
			}
			if err := stream.Close(); err != nil {
				t.Fatal(err)
			}
			<-ready
			want := bytes.Repeat([]byte{0x5a}, 1152)
			if err := c.SendDatagram(want); err != nil {
				t.Fatal(err)
			}
			got, err := c.ReceiveDatagram(ctx)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatal("logical control close broke packet mode", err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, kind := range []string{"udp", "unknown"} {
		if _, err := ListenTunnel("127.0.0.1:0", nil, kind); err == nil {
			t.Fatal("unknown listener accepted")
		}
		if _, err := DialTunnel(context.Background(), "127.0.0.1:0", nil, kind); err == nil {
			t.Fatal("unknown transport accepted")
		}
	}
}

func TestTCPRejectsInvalidTLS(t *testing.T) {
	cert, key, ca := writeTestCertificates(t)
	for _, kind := range []string{"wrong_name", "untrusted", "wrong_alpn", "missing_alpn", "insecure", "nil"} {
		t.Run(kind, func(t *testing.T) {
			sCfg, _ := ServerTLS(cert, key)
			cCfg, _ := ClientTLS(ca, "localhost")
			switch kind {
			case "wrong_name":
				cCfg.ServerName = "wrong.example"
			case "untrusted":
				cCfg.RootCAs = x509.NewCertPool()
			case "wrong_alpn":
				sCfg.NextProtos = []string{"wrong"}
			case "missing_alpn":
				sCfg.NextProtos = nil
			case "insecure":
				cCfg.InsecureSkipVerify = true
			case "nil":
				cCfg = nil
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			l, err := ListenTunnel("127.0.0.1:0", sCfg, "tcp")
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			go func() {
				c, err := l.Accept(ctx)
				if err != nil {
					return
				}
				defer c.CloseWithError(0, "test")
				_, _ = c.AcceptControl(ctx)
			}()
			if c, err := DialTunnel(ctx, l.Addr().String(), cCfg, "tcp"); err == nil {
				_ = c.CloseWithError(0, "test")
				t.Fatal("invalid TLS connection accepted")
			}
		})
	}
	if _, err := ListenTunnel("127.0.0.1:0", nil, "tcp"); err == nil {
		t.Fatal("TLS listener accepted missing config")
	}
}

func TestTCPControlLifetime(t *testing.T) {
	t.Run("control_transition_and_single_open", func(t *testing.T) {
		local, peer := net.Pipe()
		defer peer.Close()
		c := newTCPConn(local, local)
		defer c.CloseWithError(0, "test")
		if c.SendDatagram([]byte{1, 2}) == nil {
			t.Fatal("packet accepted before authentication")
		}
		ctx, cancel := context.WithCancel(context.Background())
		stream, err := c.OpenControl(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.OpenControl(ctx); err == nil {
			t.Fatal("duplicate control stream accepted")
		}
		if err := stream.Close(); err != nil {
			t.Fatal(err)
		}
		cancel()
		if c.Context().Err() != nil {
			t.Fatal("ending auth context closed authenticated connection")
		}
		go func() { _ = writeFrame(peer, []byte("packet")) }()
		dataCtx, cancelData := context.WithTimeout(context.Background(), time.Second)
		defer cancelData()
		if p, err := c.ReceiveDatagram(dataCtx); err != nil || string(p) != "packet" {
			t.Fatal("control deadline/cancellation leaked into packet mode", err)
		}
	})
	t.Run("cancel_control_read", func(t *testing.T) {
		local, peer := net.Pipe()
		defer peer.Close()
		c := newTCPConn(local, local)
		defer c.CloseWithError(0, "test")
		ctx, cancel := context.WithCancel(context.Background())
		stream, err := c.AcceptControl(ctx)
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { _, err := protocol.ReadMessage(stream); done <- err }()
		cancel()
		select {
		case err := <-done:
			if err == nil || stream.Close() == nil {
				t.Fatal("canceled control became a data connection")
			}
		case <-time.After(time.Second):
			t.Fatal("canceled control read blocked")
		}
	})
	t.Run("close_interrupts_blocked_write", func(t *testing.T) {
		c, _ := pipeConn(t)
		done := make(chan error, 1)
		go func() { done <- c.SendDatagram([]byte{1, 2}) }()
		_ = c.CloseWithError(0, "test close")
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("closed connection accepted write")
			}
		case <-time.After(time.Second):
			t.Fatal("close did not interrupt writer")
		}
	})
}

func TestTCPListenerDoesNotSerializeTLSHandshakes(t *testing.T) {
	cert, key, ca := writeTestCertificates(t)
	serverTLS, _ := ServerTLS(cert, key)
	clientTLS, _ := ClientTLS(ca, "localhost")
	l, err := ListenTunnel("127.0.0.1:0", serverTLS, "tcp")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	stalled, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer stalled.Close()
	first, err := l.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer first.CloseWithError(0, "test")
	go func() { _, _ = first.AcceptControl(ctx) }()
	done := make(chan error, 1)
	go func() {
		second, err := l.Accept(ctx)
		if err != nil {
			done <- err
			return
		}
		defer second.CloseWithError(0, "test")
		_, err = second.AcceptControl(ctx)
		done <- err
		<-ctx.Done()
	}()
	c, err := DialTunnel(ctx, l.Addr().String(), clientTLS, "tcp")
	if err != nil {
		t.Fatal("stalled handshake blocked a new client:", err)
	}
	defer c.CloseWithError(0, "test")
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
