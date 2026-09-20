package socks5proxy

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
)

func handleProxyRequest(local *net.TCPConn, server *net.TCPAddr, auth socks5Auth, mode string) error {
	options, _ := (ProxyOptions{}).normalized()
	return handleProxySession(context.Background(), local, server.String(), auth, mode, options)
}

func handleProxySession(ctx context.Context, local net.Conn, remote string, auth socks5Auth, mode string, options ProxyOptions) error {
	defer local.Close() // Includes dial failure and protocol validation failure.
	handshakeCtx, cancel := context.WithTimeout(ctx, options.HandshakeTimeout)
	defer cancel()
	deadline, _ := handshakeCtx.Deadline()
	local.SetDeadline(deadline)
	remoteConn, err := dialProxy(handshakeCtx, remote, options)
	if err != nil {
		if mode == "http" {
			writeHTTPError(local, 502)
		}
		return err
	}
	defer remoteConn.Close()
	stop := context.AfterFunc(ctx, func() { remoteConn.Close() })
	defer stop()
	remoteConn.SetDeadline(deadline)
	wire := &cipherConn{remoteConn, auth}
	switch mode {
	case "http":
		return handleHTTPProxy(ctx, local, wire, options)
	case "socks5":
		greeting := make([]byte, 2)
		if _, err := io.ReadFull(local, greeting); err != nil {
			return err
		}
		methods := make([]byte, int(greeting[1]))
		if _, err := io.ReadFull(local, methods); err != nil {
			return err
		}
		if err := writeProxy(wire, append(greeting, methods...)); err != nil {
			return err
		}
		response := make([]byte, 2)
		if _, err := io.ReadFull(wire, response); err != nil {
			return err
		}
		if err := writeProxy(local, response); err != nil {
			return err
		}
		if response[0] != 5 || response[1] != 0 {
			return errors.New("SOCKS authentication negotiation failed")
		}
		request, err := readRequestFrame(local)
		if err != nil {
			return err
		}
		if err := writeProxy(wire, request); err != nil {
			return err
		}
		response, err = readRequestFrame(wire)
		if err != nil {
			return err
		}
		if err := writeProxy(local, response); err != nil {
			return err
		}
		if response[0] != 5 || response[1] != 0 {
			return errors.New("SOCKS destination connection failed")
		}
		cancel()
		return relayProxy(ctx, local, wire, nil, options.IdleTimeout)
	default:
		return errors.New("recv 参数仅支持 http 或 socks5")
	}
}

// Client retains the original blocking API using default resource limits.
func Client(local, remote, obfs, password, mode string) error {
	return ClientContext(context.Background(), local, remote, obfs, password, mode, ProxyOptions{})
}

// ClientContext serves an HTTP or SOCKS5 application proxy until cancellation.
func ClientContext(ctx context.Context, local, remote, obfs, password, mode string, options ProxyOptions) error {
	if mode != "http" && mode != "socks5" {
		return errors.New("recv 参数仅支持 http 或 socks5")
	}
	options, err := options.normalized()
	if err != nil {
		return err
	}
	if err := validateProxyAddress(remote); err != nil {
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
	log.Printf("监听本地端口: %s; 远程服务器: %s", listener.Addr(), remote)
	return serveProxy(ctx, listener, options, func(ctx context.Context, conn net.Conn) error {
		return handleProxySession(ctx, conn, remote, auth, mode, options)
	})
}
