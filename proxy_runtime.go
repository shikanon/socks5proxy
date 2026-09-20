package socks5proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"syscall"
	"time"
)

// ProxyOptions bounds resource use in application proxy mode. Zero selects the
// default; negative values are rejected. IdleTimeout measures either direction.
type ProxyOptions struct {
	MaxConnections   int
	DialTimeout      time.Duration
	HandshakeTimeout time.Duration
	IdleTimeout      time.Duration
}

func (o ProxyOptions) normalized() (ProxyOptions, error) {
	if o.MaxConnections < 0 || o.DialTimeout < 0 || o.HandshakeTimeout < 0 || o.IdleTimeout < 0 {
		return o, errors.New("proxy limits and timeouts must not be negative")
	}
	if o.MaxConnections == 0 {
		o.MaxConnections = 256
	}
	if o.DialTimeout == 0 {
		o.DialTimeout = 10 * time.Second
	}
	if o.HandshakeTimeout == 0 {
		o.HandshakeTimeout = 10 * time.Second
	}
	if o.IdleTimeout == 0 {
		o.IdleTimeout = 5 * time.Minute
	}
	return o, nil
}

// serveProxy owns the listener and all accepted connections. Acquire before
// Accept so excess clients stay in the bounded kernel backlog, not in goroutines.
func serveProxy(ctx context.Context, listener net.Listener, options ProxyOptions, handle func(context.Context, net.Conn) error) error {
	ctx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer func() {
		cancel()
		listener.Close()
		workers.Wait()
		stop()
	}()
	slots := make(chan struct{}, options.MaxConnections)
	var backoff time.Duration
	for {
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			return nil
		}
		conn, err := listener.Accept()
		if err != nil {
			<-slots
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) ||
				errors.Is(err, syscall.ENOBUFS) || errors.Is(err, syscall.ENOMEM) ||
				errors.Is(err, syscall.EINTR) || errors.Is(err, syscall.ECONNABORTED) ||
				(errors.As(err, &ne) && ne.Timeout()) {
				if backoff == 0 {
					backoff = 5 * time.Millisecond
				} else {
					backoff *= 2
				}
				if backoff > time.Second {
					backoff = time.Second
				}
				log.Printf("proxy accept: %v; retry in %s (check FD limit and -max-connections)", err, backoff)
				timer := time.NewTimer(backoff)
				select {
				case <-ctx.Done():
					timer.Stop()
					return nil
				case <-timer.C:
				}
				continue
			}
			return err
		}
		backoff = 0
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer func() { <-slots }()
			defer conn.Close()
			stopConn := context.AfterFunc(ctx, func() { conn.Close() })
			defer stopConn()
			if err := handle(ctx, conn); err != nil && ctx.Err() == nil {
				log.Printf("proxy %s: %v", conn.RemoteAddr(), err)
			}
		}()
	}
}

func dialProxy(ctx context.Context, address string, options ProxyOptions) (net.Conn, error) {
	return (&net.Dialer{Timeout: options.DialTimeout}).DialContext(ctx, "tcp", address)
}

// proxyActivity refreshes both endpoints on progress in either direction.
// Serialize refreshes so an older deadline cannot overwrite a newer one.
type proxyActivity struct {
	mu   sync.Mutex
	a, b net.Conn
	idle time.Duration
}

func (a *proxyActivity) touch() {
	a.mu.Lock()
	defer a.mu.Unlock()
	deadline := time.Now().Add(a.idle)
	a.a.SetDeadline(deadline)
	a.b.SetDeadline(deadline)
}

type activityReader struct {
	io.Reader
	activity *proxyActivity
}

func (r activityReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if n > 0 {
		r.activity.touch()
	}
	return n, err
}

type activityWriter struct {
	io.Writer
	activity *proxyActivity
}

func (w activityWriter) Write(p []byte) (int, error) {
	n, err := w.Writer.Write(p)
	if n > 0 {
		w.activity.touch()
	}
	return n, err
}

func closeWrite(conn net.Conn) error {
	if half, ok := conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return conn.Close()
}

// relayProxy preserves a normal TCP half-close and drains the reverse stream.
// An error, cancellation or idle deadline instead closes both directions.
func relayProxy(ctx context.Context, a, b net.Conn, aReader io.Reader, idle time.Duration) error {
	if aReader == nil {
		aReader = a
	}
	activity := &proxyActivity{a: a, b: b, idle: idle}
	activity.touch()
	stop := context.AfterFunc(ctx, func() { a.Close(); b.Close() })
	defer stop()
	results := make(chan error, 2)
	copyOne := func(dst net.Conn, src io.Reader) {
		_, err := io.Copy(activityWriter{dst, activity}, activityReader{src, activity})
		if err == nil {
			err = closeWrite(dst)
		}
		if err != nil {
			a.Close()
			b.Close()
		}
		results <- err
	}
	go copyOne(b, aReader)
	go copyOne(a, b)
	first, second := <-results, <-results
	if first != nil {
		return first
	}
	return second
}

// cipherConn applies the existing stateless byte substitution without mutating
// the caller's write buffer. It does not provide encryption or authentication.
type cipherConn struct {
	net.Conn
	auth socks5Auth
}

func (c *cipherConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		if decodeErr := c.auth.Decrypt(p[:n]); decodeErr != nil {
			return 0, decodeErr
		}
	}
	return n, err
}
func (c *cipherConn) Write(p []byte) (int, error) {
	buf := append([]byte(nil), p...)
	if err := c.auth.Encrypt(buf); err != nil {
		return 0, err
	}
	return c.Conn.Write(buf)
}
func (c *cipherConn) CloseWrite() error { return closeWrite(c.Conn) }

func writeProxy(w io.Writer, p []byte) error {
	n, err := w.Write(p)
	if err == nil && n != len(p) {
		return io.ErrShortWrite
	}
	return err
}

func validateProxyAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	if host == "" {
		return errors.New("remote host must not be empty")
	}
	if _, err := net.LookupPort("tcp", port); err != nil {
		return fmt.Errorf("invalid remote port: %w", err)
	}
	return nil
}
