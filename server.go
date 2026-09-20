package socks5proxy

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"strconv"
	"time"
)

func handleHandshake(client io.ReadWriter, auth socks5Auth, _ []byte, proto *ProtocolVersion) error {
	header, err := readEncryptedFull(client, auth, 2)
	if err != nil {
		return err
	}
	methods, err := readEncryptedFull(client, auth, int(header[1]))
	if err != nil {
		return err
	}
	response, handshakeErr := proto.HandleHandshake(append(header, methods...))
	if len(response) > 0 {
		n, err := auth.EncodeWrite(client, response)
		if err != nil {
			return err
		}
		if n != len(response) {
			return io.ErrShortWrite
		}
	}
	return handshakeErr
}

func readEncryptedFull(reader io.Reader, auth socks5Auth, size int) ([]byte, error) {
	buf := make([]byte, size)
	if _, err := io.ReadFull(reader, buf); err != nil {
		return nil, err
	}
	if err := auth.Decrypt(buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// readRequestFrame reads just one SOCKS request, preserving any pipelined data.
func readRequestFrame(reader io.Reader) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	var remaining int
	switch header[3] {
	case 1:
		remaining = net.IPv4len + 2
	case 3:
		length := make([]byte, 1)
		if _, err := io.ReadFull(reader, length); err != nil {
			return nil, err
		}
		if length[0] == 0 {
			return nil, errors.New("域名长度错误")
		}
		header = append(header, length...)
		remaining = int(length[0]) + 2
	case 4:
		remaining = net.IPv6len + 2
	default:
		return nil, errors.New("IP地址错误")
	}
	tail := make([]byte, remaining)
	if _, err := io.ReadFull(reader, tail); err != nil {
		return nil, err
	}
	return append(header, tail...), nil
}

type cipherReader struct {
	io.Reader
	auth socks5Auth
}

func (r cipherReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if n > 0 {
		if decodeErr := r.auth.Decrypt(p[:n]); decodeErr != nil {
			return 0, decodeErr
		}
	}
	return n, err
}

func handleRequest(client io.ReadWriter, auth socks5Auth, request *Socks5Resolution) error {
	payload, err := readRequestFrame(cipherReader{client, auth})
	if err != nil {
		return err
	}
	_, err = request.parseRequest(payload)
	return err
}

func socksReply(code byte) []byte {
	return []byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0}
}

func handleClientRequest(client *net.TCPConn, auth socks5Auth) error {
	if client == nil {
		return nil
	}
	options, _ := (ProxyOptions{}).normalized()
	return handleServerSession(context.Background(), client, auth, options)
}

func handleServerSession(ctx context.Context, client net.Conn, auth socks5Auth, options ProxyOptions) error {
	defer client.Close()
	handshakeCtx, cancel := context.WithTimeout(ctx, options.HandshakeTimeout)
	defer cancel()
	client.SetDeadline(time.Now().Add(options.HandshakeTimeout))
	wire := &cipherConn{client, auth}
	var proto ProtocolVersion
	if err := handleHandshake(client, auth, nil, &proto); err != nil {
		return err
	}
	var request Socks5Resolution
	if err := handleRequest(client, auth, &request); err != nil {
		_ = writeProxy(wire, socksReply(1))
		return err
	}
	host := request.DSTDOMAIN
	if host == "" {
		host = net.IP(request.DSTADDR).String()
	}
	address := net.JoinHostPort(host, strconv.Itoa(int(request.DSTPORT)))
	target, err := dialProxy(handshakeCtx, address, options)
	if err != nil {
		_ = writeProxy(wire, socksReply(5))
		return err
	}
	defer target.Close()
	if err := writeProxy(wire, socksReply(0)); err != nil {
		return err
	}
	cancel()
	return relayProxy(ctx, wire, target, nil, options.IdleTimeout)
}

// Server retains the original blocking API using default resource limits.
func Server(local, obfs, password string) error {
	return ServerContext(context.Background(), local, obfs, password, ProxyOptions{})
}

// ServerContext serves the obfuscated SOCKS proxy until cancellation.
func ServerContext(ctx context.Context, local, obfs, password string, options ProxyOptions) error {
	options, err := options.normalized()
	if err != nil {
		return err
	}
	auth, err := CreateAuth(obfs, password)
	if err != nil {
		return err
	}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", local)
	if err != nil {
		return err
	}
	log.Printf("监听服务器端口: %s", listener.Addr())
	return serveProxy(ctx, listener, options, func(ctx context.Context, conn net.Conn) error {
		return handleServerSession(ctx, conn, auth, options)
	})
}
