package transport

import (
	"context"
	"errors"
	"time"

	"github.com/shikanon/socks5proxy/internal/keytable"
)

type tableConn struct {
	Conn
	table *keytable.Table
}

// WithTable maps complete datagrams after the TCP control authentication.
func WithTable(conn Conn, table *keytable.Table) Conn {
	return &tableConn{Conn: conn, table: table}
}

func (c *tableConn) SendDatagram(payload []byte) error {
	if len(payload) == 0 || len(payload) > maxTCPDatagram {
		return errors.New("invalid table tunnel packet size")
	}
	return c.Conn.SendDatagram(c.table.Encode(payload, time.Now()))
}

func (c *tableConn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	payload, err := c.Conn.ReceiveDatagram(ctx)
	if err != nil {
		return nil, err
	}
	if len(payload) > maxTCPDatagram+keytable.HeaderSize {
		_ = c.CloseWithError(3, "oversized table frame")
		return nil, errors.New("oversized table frame")
	}
	decoded, err := c.table.Decode(payload, time.Now())
	if err != nil {
		_ = c.CloseWithError(3, "invalid table frame")
	}
	return decoded, err
}
