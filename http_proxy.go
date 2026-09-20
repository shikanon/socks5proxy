package socks5proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
)

const maxProxyHeader = 32 << 10

var errProxyHeaderTooLarge = errors.New("HTTP proxy header exceeds 32 KiB")

func writeHTTPError(conn net.Conn, status int) {
	body := http.StatusText(status) + "\n"
	_, _ = fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nConnection: close\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s", status, http.StatusText(status), len(body), body)
}

func readProxyHTTPRequest(conn io.Reader) (*http.Request, *bufio.Reader, error) {
	reader := bufio.NewReader(conn)
	header := make([]byte, 0, 4096)
	// Bound the request line and headers only; request bodies remain streaming.
	lineStart := 0
	for {
		b, err := reader.ReadByte()
		if err != nil {
			return nil, nil, err
		}
		header = append(header, b)
		if len(header) > maxProxyHeader {
			return nil, nil, errProxyHeaderTooLarge
		}
		if b == '\n' {
			line := header[lineStart:]
			if bytes.Equal(line, []byte("\r\n")) || bytes.Equal(line, []byte("\n")) {
				break
			}
			lineStart = len(header)
		}
	}
	combined := bufio.NewReader(io.MultiReader(bytes.NewReader(header), reader))
	request, err := http.ReadRequest(combined)
	return request, combined, err
}

func httpProxyTarget(request *http.Request) (string, error) {
	var address string
	if request.Method == http.MethodConnect {
		address = request.Host
		if request.URL.Host != address || request.URL.User != nil {
			return "", errors.New("invalid CONNECT target")
		}
	} else {
		if request.URL.Scheme != "http" || request.URL.Host == "" || request.URL.User != nil {
			return "", errors.New("HTTP proxy requires an absolute http URL")
		}
		address = request.URL.Host
		if request.URL.Port() == "" {
			address = net.JoinHostPort(request.URL.Hostname(), "80")
		}
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || strings.ContainsAny(host, "\x00\r\n\t /?#@") {
		return "", errors.New("invalid proxy destination")
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return "", errors.New("invalid proxy destination port")
	}
	return net.JoinHostPort(host, strconv.Itoa(number)), nil
}

func connectSOCKS(wire net.Conn, address string) error {
	if err := writeProxy(wire, []byte{5, 1, 0}); err != nil {
		return err
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(wire, response); err != nil {
		return err
	}
	if !bytes.Equal(response, []byte{5, 0}) {
		return errors.New("SOCKS negotiation failed")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	packet := []byte{5, 1, 0}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			packet = append(append(packet, 1), ip4...)
		} else {
			packet = append(append(packet, 4), ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return errors.New("SOCKS destination name too long")
		}
		packet = append(packet, 3, byte(len(host)))
		packet = append(packet, host...)
	}
	number, err := strconv.Atoi(port)
	if err != nil {
		return err
	}
	packet = append(packet, byte(number>>8), byte(number))
	if err := writeProxy(wire, packet); err != nil {
		return err
	}
	response, err = readRequestFrame(wire)
	if err != nil {
		return err
	}
	if response[0] != 5 || response[1] != 0 || response[2] != 0 {
		return errors.New("SOCKS destination connection failed")
	}
	return nil
}

func handleHTTPProxy(ctx context.Context, local, wire net.Conn, options ProxyOptions) error {
	request, reader, err := readProxyHTTPRequest(local)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, errProxyHeaderTooLarge) {
			status = http.StatusRequestHeaderFieldsTooLarge
		}
		writeHTTPError(local, status)
		return err
	}
	address, err := httpProxyTarget(request)
	if err != nil {
		writeHTTPError(local, 400)
		return err
	}
	if err := connectSOCKS(wire, address); err != nil {
		writeHTTPError(local, 502)
		return err
	}
	if request.Method == http.MethodConnect {
		if err := writeProxy(local, []byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
			return err
		}
		return relayProxy(ctx, local, wire, reader, options.IdleTimeout)
	}
	// One request per local HTTP connection. Request.Write streams the complete
	// body (including chunked bodies) and emits an origin-form request target.
	for _, value := range request.Header.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			request.Header.Del(strings.TrimSpace(name))
		}
	}
	for _, name := range []string{"Proxy-Connection", "Proxy-Authorization", "Proxy-Authenticate", "Connection", "Keep-Alive", "TE", "Upgrade"} {
		request.Header.Del(name)
	}
	request.Close = true
	request.Host = request.URL.Host
	request.RequestURI = ""
	activity := &proxyActivity{a: local, b: wire, idle: options.IdleTimeout}
	activity.touch()
	request.Body = struct {
		io.Reader
		io.Closer
	}{activityReader{request.Body, activity}, request.Body}
	done := make(chan error, 1)
	go func() {
		err := request.Write(activityWriter{wire, activity})
		if err == nil {
			err = closeWrite(wire)
		}
		if err != nil {
			local.Close()
			wire.Close()
		}
		done <- err
	}()
	// Read concurrently so Expect: 100-continue and early responses work.
	_, copyErr := io.Copy(activityWriter{local, activity}, activityReader{wire, activity})
	local.Close()
	wire.Close()
	writeErr := <-done
	request.Body.Close()
	if copyErr != nil {
		return copyErr
	}
	return writeErr
}
