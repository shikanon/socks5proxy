package server

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shikanon/socks5proxy/internal/tunnel/protocol"
	"github.com/shikanon/socks5proxy/internal/tunnel/transport"
)

type session struct {
	id        string
	clientID  string
	addr      netip.Addr
	addr6     netip.Addr
	mtu       int
	obfs      string
	cipher    protocol.Cipher
	conn      transport.Conn
	send      chan []byte
	started   time.Time
	sentBytes atomic.Uint64
	recvBytes atomic.Uint64
	dropped   atomic.Uint64
}

type sessionTable struct {
	mu       sync.RWMutex
	byClient map[string]*session
	byAddr   map[netip.Addr]*session
}

func newSessionTable() *sessionTable {
	return &sessionTable{
		byClient: make(map[string]*session),
		byAddr:   make(map[netip.Addr]*session),
	}
}

func (t *sessionTable) register(current *session) *session {
	t.mu.Lock()
	defer t.mu.Unlock()
	previous := t.byClient[current.clientID]
	if previous != nil {
		delete(t.byAddr, previous.addr)
		delete(t.byAddr, previous.addr6)
	}
	t.byClient[current.clientID] = current
	t.byAddr[current.addr] = current
	if current.addr6.IsValid() {
		t.byAddr[current.addr6] = current
	}
	return previous
}

func (t *sessionTable) remove(current *session) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.byClient[current.clientID] != current {
		return
	}
	delete(t.byClient, current.clientID)
	delete(t.byAddr, current.addr)
	delete(t.byAddr, current.addr6)
}

func (t *sessionTable) byAddress(addr netip.Addr) *session {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.byAddr[addr]
}

func (t *sessionTable) closeAll() {
	t.mu.RLock()
	sessions := make([]*session, 0, len(t.byClient))
	for _, item := range t.byClient {
		sessions = append(sessions, item)
	}
	t.mu.RUnlock()
	for _, item := range sessions {
		_ = item.conn.CloseWithError(0, "server shutdown")
	}
}
