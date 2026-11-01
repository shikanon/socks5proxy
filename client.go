package socks5proxy

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
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
	switch mode {
	case "http":
		request, reader, err := readProxyHTTPRequest(local)
		if err != nil {
			status := 400
			if errors.Is(err, errProxyHeaderTooLarge) {
				status = 431
			}
			writeHTTPError(local, status)
			return err
		}
		defer request.Body.Close()
		address, err := httpProxyTarget(request)
		if err != nil {
			writeHTTPError(local, 400)
			return err
		}
		target, err := dialDestination(handshakeCtx, address, remote, auth, options)
		if err != nil {
			writeHTTPError(local, 502)
			return err
		}
		defer target.Close()
		stop := context.AfterFunc(ctx, func() { target.Close() })
		defer stop()
		cancel()
		return forwardHTTPRequest(ctx, local, target, request, reader, options)
	case "socks5":
		greeting := make([]byte, 2)
		if _, err := io.ReadFull(local, greeting); err != nil {
			return err
		}
		methods := make([]byte, int(greeting[1]))
		if _, err := io.ReadFull(local, methods); err != nil {
			return err
		}
		var proto ProtocolVersion
		response, handshakeErr := proto.HandleHandshake(append(greeting, methods...))
		if len(response) > 0 {
			if err := writeProxy(local, response); err != nil {
				return err
			}
		}
		if handshakeErr != nil {
			return handshakeErr
		}
		request, err := readRequestFrame(local)
		if err != nil {
			_ = writeProxy(local, socksReply(1))
			return err
		}
		var destination Socks5Resolution
		if _, err := destination.parseRequest(request); err != nil {
			_ = writeProxy(local, socksReply(7))
			return err
		}
		if destination.DSTPORT == 0 {
			_ = writeProxy(local, socksReply(1))
			return errors.New("SOCKS destination port must not be zero")
		}
		host := destination.DSTDOMAIN
		if host == "" {
			host = net.IP(destination.DSTADDR).String()
		}
		address := net.JoinHostPort(host, strconv.Itoa(int(destination.DSTPORT)))
		target, err := dialDestination(handshakeCtx, address, remote, auth, options)
		if err != nil {
			_ = writeProxy(local, socksReply(5))
			return err
		}
		defer target.Close()
		stop := context.AfterFunc(ctx, func() { target.Close() })
		defer stop()
		if err := writeProxy(local, socksReply(0)); err != nil {
			return err
		}
		cancel()
		return relayProxy(ctx, local, target, nil, options.IdleTimeout)
	default:
		return errors.New("recv 参数仅支持 http 或 socks5")
	}
}

// dialDestination chooses the route before dialing or doing DNS. A matched host
// keeps remote DNS and never falls back to a direct connection on failure.
func dialDestination(ctx context.Context, address, remote string, auth socks5Auth, options ProxyOptions) (net.Conn, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil || host == "" || strings.ContainsAny(host, "\x00\r\n\t /?#@") {
		return nil, errors.New("invalid proxy destination")
	}
	if options.Scope == "rules" && !options.Rules.Match(host) {
		return dialProxy(ctx, address, options)
	}
	conn, err := dialProxy(ctx, remote, options)
	if err != nil {
		return nil, err
	}
	// Cancellation must also interrupt the SOCKS handshake after DialContext.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	wire := &cipherConn{conn, auth}
	if err := connectSOCKS(wire, address); err != nil {
		conn.Close()
		return nil, err
	}
	return wire, nil
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
	return serveClientProxy(ctx, listener, remote, auth, mode, options)
}
