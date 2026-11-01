package transport

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shikanon/socks5proxy/internal/tunnel/protocol"
)

const (
	fragmentType       = 3
	fragmentHeader     = 10
	fragmentChunk      = 1100
	unfragmentedLimit  = 1152
	fragmentPacketMax  = 1402
	fragmentPendingMax = 64
	fragmentLifetime   = 5 * time.Second
)

type fragmentAssembly struct {
	created time.Time
	total   int
	mask    uint8
	data    []byte
}

type fragmentConn struct {
	Conn
	id      atomic.Uint32
	mu      sync.Mutex
	pending map[uint32]*fragmentAssembly
}

// WithFragmentation is enabled only after both QUIC peers negotiate IPv6.
// Small legacy frames stay unchanged; larger frames fit even a minimum QUIC path.
func WithFragmentation(conn Conn) Conn {
	return &fragmentConn{Conn: conn, pending: make(map[uint32]*fragmentAssembly)}
}

func (c *fragmentConn) SendDatagram(payload []byte) error {
	if len(payload) < 3 || len(payload) > fragmentPacketMax {
		return errors.New("invalid fragmented datagram size")
	}
	if len(payload) <= unfragmentedLimit {
		return c.Conn.SendDatagram(payload)
	}
	id := c.id.Add(1)
	for offset := 0; offset < len(payload); offset += fragmentChunk {
		end := min(offset+fragmentChunk, len(payload))
		frame := make([]byte, fragmentHeader+end-offset)
		frame[0], frame[1] = protocol.Version, fragmentType
		binary.BigEndian.PutUint32(frame[2:6], id)
		binary.BigEndian.PutUint16(frame[6:8], uint16(len(payload)))
		binary.BigEndian.PutUint16(frame[8:10], uint16(offset))
		copy(frame[fragmentHeader:], payload[offset:end])
		if err := c.Conn.SendDatagram(frame); err != nil {
			return err
		}
	}
	return nil
}

func (c *fragmentConn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	for {
		frame, err := c.Conn.ReceiveDatagram(ctx)
		if err != nil {
			return nil, err
		}
		if _, _, ok := protocol.ParseHeartbeat(frame); ok {
			return frame, nil
		}
		if len(frame) >= 3 && len(frame) <= unfragmentedLimit && frame[0] == protocol.Version &&
			(frame[1] == protocol.DatagramTypeIPv4 || frame[1] == protocol.DatagramTypeIPv6) {
			return frame, nil
		}
		if packet := c.assemble(frame, time.Now()); packet != nil {
			return packet, nil
		}
	}
}

func (c *fragmentConn) assemble(frame []byte, now time.Time) []byte {
	if len(frame) <= fragmentHeader || frame[0] != protocol.Version || frame[1] != fragmentType {
		return nil
	}
	id := binary.BigEndian.Uint32(frame[2:6])
	total, offset := int(binary.BigEndian.Uint16(frame[6:8])), int(binary.BigEndian.Uint16(frame[8:10]))
	if total <= unfragmentedLimit || total > fragmentPacketMax || (offset != 0 && offset != fragmentChunk) ||
		len(frame)-fragmentHeader != min(fragmentChunk, total-offset) {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, item := range c.pending {
		if now.Sub(item.created) >= fragmentLifetime {
			delete(c.pending, key)
		}
	}
	item := c.pending[id]
	if item == nil {
		if len(c.pending) >= fragmentPendingMax {
			var oldest uint32
			var earliest time.Time
			for key, entry := range c.pending {
				if earliest.IsZero() || entry.created.Before(earliest) {
					oldest, earliest = key, entry.created
				}
			}
			delete(c.pending, oldest)
		}
		item = &fragmentAssembly{created: now, total: total, data: make([]byte, total)}
		c.pending[id] = item
	}
	if item.mask == 3 {
		return nil // Retain a bounded tombstone against duplicate complete frames.
	}
	if item.total != total {
		item.mask, item.data = 3, nil
		return nil
	}
	bit := uint8(1 << (offset / fragmentChunk))
	end := offset + len(frame) - fragmentHeader
	if item.mask&bit != 0 {
		if !bytes.Equal(item.data[offset:end], frame[fragmentHeader:]) {
			item.mask, item.data = 3, nil
		}
		return nil
	}
	copy(item.data[offset:end], frame[fragmentHeader:])
	item.mask |= bit
	if item.mask != 3 {
		return nil
	}
	packet := item.data
	item.data = nil
	if packet[0] != protocol.Version || (packet[1] != protocol.DatagramTypeIPv4 && packet[1] != protocol.DatagramTypeIPv6) {
		return nil
	}
	return packet
}
