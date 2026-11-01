package client

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"github.com/shikanon/socks5proxy/internal/tunnel/protocol"
	"github.com/shikanon/socks5proxy/internal/tunnel/transport"
)

var errHealthTimeout = errors.New("remote tunnel connectivity timed out")

type healthOptions struct {
	interval, timeout time.Duration
	dnsName           string
}

// probe runs before any routes are installed. Cancellation also interrupts a
// blocked SendDatagram, which has no context argument in the transport API.
func probe(ctx context.Context, conn transport.Conn, response protocol.Message, cipher protocol.Cipher, options healthOptions) (result error) {
	m, err := newConnectionHealth(response, cipher, options)
	if err != nil {
		return err
	}
	probeCtx, cancel := context.WithTimeout(ctx, options.timeout)
	stop := context.AfterFunc(probeCtx, func() { _ = conn.CloseWithError(0, "probe timed out") })
	// TCP cancellation closes the whole socket. Keep one receive on the overall
	// probe context, and stop requesting reads once all paths have replied.
	type received struct {
		payload []byte
		err     error
	}
	next := make(chan struct{}, 1)
	replies := make(chan received, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range next {
			payload, err := conn.ReceiveDatagram(probeCtx)
			replies <- received{payload, err}
			if err != nil {
				return
			}
		}
	}()
	defer func() {
		close(next)
		if result != nil {
			cancel()
			_ = conn.CloseWithError(0, "probe failed")
		}
		<-done
		stopped := stop()
		if !stopped || probeCtx.Err() != nil {
			if result == nil {
				result = errors.Join(errHealthTimeout, probeCtx.Err())
			}
			_ = conn.CloseWithError(0, "probe canceled")
		}
		cancel()
	}()
	send := func() error {
		payloads, err := m.requests()
		if err != nil {
			return err
		}
		for _, payload := range payloads {
			if err := conn.SendDatagram(payload); err != nil {
				return err
			}
		}
		return nil
	}
	if err := send(); err != nil {
		return err
	}
	next <- struct{}{}
	ticker := time.NewTicker(options.interval)
	defer ticker.Stop()
	for {
		select {
		case <-probeCtx.Done():
			return errors.Join(errHealthTimeout, probeCtx.Err())
		case <-ticker.C:
			if err := send(); err != nil {
				return err
			}
		case reply := <-replies:
			if reply.err != nil {
				if probeCtx.Err() != nil {
					return errors.Join(errHealthTimeout, probeCtx.Err())
				}
				return reply.err
			}
			m.receive(reply.payload)
			if m.ready() {
				return nil
			}
			next <- struct{}{}
		}
	}
}

func randomNonce() uint64 {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		panic(err)
	}
	return binary.BigEndian.Uint64(raw[:])
}

type healthMonitor struct {
	options   healthOptions
	mu        sync.Mutex
	last      time.Time
	pending   map[uint64]time.Time
	heartbeat bool
	verified  bool
	paths     []dnsPath
	mtu       int
	cipher    protocol.Cipher
}

func newHealthMonitor(options healthOptions) *healthMonitor {
	return &healthMonitor{options: options, last: time.Now(), pending: make(map[uint64]time.Time), heartbeat: true}
}

func newConnectionHealth(r protocol.Message, cipher protocol.Cipher, options healthOptions) (*healthMonitor, error) {
	paths, err := newDNSPaths(r, options.dnsName)
	if err != nil {
		return nil, err
	}
	m := newHealthMonitor(options)
	m.paths, m.heartbeat, m.mtu, m.cipher = paths, r.Heartbeat, r.MTU, cipher
	return m, nil
}

func (m *healthMonitor) pong(nonce uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	if sent, ok := m.pending[nonce]; ok && now.Sub(sent) < m.options.timeout {
		m.last, m.verified = now, true
		delete(m.pending, nonce)
	}
}

func (m *healthMonitor) expired() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.remaining() <= 0
}

// Caller holds the mutex. Both address families must remain usable.
func (m *healthMonitor) remaining() time.Duration {
	left := m.options.timeout
	if m.heartbeat {
		left = min(left, m.options.timeout-time.Since(m.last))
	}
	for _, p := range m.paths {
		left = min(left, m.options.timeout-time.Since(p.last))
	}
	return left
}

func (m *healthMonitor) ready() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.remaining() <= 0 {
		return false
	}
	if m.heartbeat && !m.verified {
		return false
	}
	for _, p := range m.paths {
		if !p.verified {
			return false
		}
	}
	return true
}

func (m *healthMonitor) receive(payload []byte) {
	if kind, nonce, ok := protocol.ParseHeartbeat(payload); ok {
		if kind == protocol.DatagramTypePong {
			m.pong(nonce)
		}
		return
	}
	packet, _, err := protocol.DecodeDatagram(payload, m.mtu, m.cipher)
	if err == nil {
		m.packet(packet)
	}
}

func (m *healthMonitor) packet(packet []byte) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.paths {
		if m.paths[i].reply(packet, time.Now(), m.options.timeout) {
			return true
		}
	}
	return false
}

func (m *healthMonitor) requests() ([][]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var payloads [][]byte
	now := time.Now()
	if m.heartbeat {
		nonce := randomNonce()
		for n, sent := range m.pending {
			if now.Sub(sent) >= m.options.timeout {
				delete(m.pending, n)
			}
		}
		m.pending[nonce] = now
		payloads = append(payloads, protocol.Heartbeat(protocol.DatagramTypePing, nonce))
	}
	for i := range m.paths {
		packet := m.paths[i].request(now, m.options.timeout)
		payload, _, err := protocol.EncodeDatagram(packet, m.mtu, m.cipher)
		if err != nil {
			return nil, err
		}
		payloads = append(payloads, payload)
	}
	return payloads, nil
}

func (m *healthMonitor) run(ctx context.Context, conn transport.Conn) error {
	// Socket I/O runs separately from the deadline controller. A stuck TCP write
	// must not extend the fail-open deadline.
	send := make(chan [][]byte, 1)
	errs := make(chan error, 1)
	done := make(chan struct{})
	writerCtx, stopWriter := context.WithCancel(ctx)
	go func() {
		defer close(done)
		for {
			select {
			case <-writerCtx.Done():
				return
			case payloads := <-send:
				for _, payload := range payloads {
					if err := conn.SendDatagram(payload); err != nil {
						errs <- err
						return
					}
				}
			}
		}
	}()
	defer func() { stopWriter(); _ = conn.CloseWithError(0, "health monitor stopped"); <-done }()
	ticker := time.NewTicker(m.options.interval)
	defer ticker.Stop()
	timer := time.NewTimer(m.options.timeout)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errs:
			return err
		case <-timer.C:
			m.mu.Lock()
			remaining := m.remaining()
			m.mu.Unlock()
			if remaining <= 0 {
				return errHealthTimeout
			}
			timer.Reset(remaining)
		case <-ticker.C:
			payloads, err := m.requests()
			if err != nil {
				return err
			}
			select {
			case send <- payloads:
			default:
			}
		}
	}
}
