package transport

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func fragmentFrame(id uint32, p []byte, offset int) []byte {
	end := min(offset+fragmentChunk, len(p))
	f := make([]byte, fragmentHeader+end-offset)
	f[0], f[1] = 1, fragmentType
	binary.BigEndian.PutUint32(f[2:6], id)
	binary.BigEndian.PutUint16(f[6:8], uint16(len(p)))
	binary.BigEndian.PutUint16(f[8:10], uint16(offset))
	copy(f[10:], p[offset:end])
	return f
}

func TestFragmentAssemblyBoundsAndConflicts(t *testing.T) {
	c := WithFragmentation(nil).(*fragmentConn)
	p := bytes.Repeat([]byte{0xa5}, 1402)
	p[0], p[1] = 1, 2
	now := time.Now()
	first, last := fragmentFrame(1, p, 0), fragmentFrame(1, p, fragmentChunk)
	if c.assemble(last, now) != nil {
		t.Fatal("partial fragment completed a packet")
	}
	if c.assemble(last, now) != nil {
		t.Fatal("duplicate fragment completed a packet")
	}
	if got := c.assemble(first, now); !bytes.Equal(got, p) {
		t.Fatal("out-of-order assembly changed payload")
	}
	if c.assemble(first, now) != nil || c.assemble(last, now) != nil {
		t.Fatal("duplicate full packet replayed")
	}
	first, last = fragmentFrame(2, p, 0), fragmentFrame(2, p, fragmentChunk)
	c.assemble(first, now)
	first[10] ^= 1
	c.assemble(first, now)
	if c.assemble(last, now) != nil {
		t.Fatal("conflicting duplicate assembled")
	}
	for id := uint32(3); id < 200; id++ {
		c.assemble(fragmentFrame(id, p, 0), now)
		if len(c.pending) > fragmentPendingMax {
			t.Fatal("unbounded fragment state")
		}
	}
	c.assemble(fragmentFrame(200, p, fragmentChunk), now.Add(fragmentLifetime))
	if len(c.pending) != 1 {
		t.Fatal("expired assemblies retained")
	}
	for _, edit := range []func([]byte){
		func(f []byte) { f[0]++ },
		func(f []byte) { f[1]++ },
		func(f []byte) { binary.BigEndian.PutUint16(f[6:8], 65535) },
		func(f []byte) { binary.BigEndian.PutUint16(f[8:10], 1) },
	} {
		f := fragmentFrame(300, p, 0)
		edit(f)
		if c.assemble(f, now) != nil || len(c.pending) != 1 {
			t.Fatal("malformed fragment changed assembly state")
		}
	}
}

func TestFragmentMinimumQUICPath(t *testing.T) {
	cert, key, ca := writeTestCertificates(t)
	serverTLS, _ := ServerTLS(cert, key)
	clientTLS, _ := ClientTLS(ca, "localhost")
	cfg := QUICConfig()
	cfg.DisablePathMTUDiscovery = true
	l, err := quic.ListenAddr("127.0.0.1:0", serverTLS, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	a, err := quic.DialAddr(ctx, l.Addr().String(), clientTLS, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer a.CloseWithError(0, "test complete")
	b, err := l.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer b.CloseWithError(0, "test complete")
	client, server := WithFragmentation(&quicConn{a}), WithFragmentation(&quicConn{b})
	for _, pair := range [][2]Conn{{client, server}, {server, client}} {
		for _, size := range []int{1152, 1282, 1402} {
			p := bytes.Repeat([]byte{0xa5}, size)
			p[0], p[1] = 1, 2
			if err := pair[0].SendDatagram(p); err != nil {
				t.Fatal("send over minimum path failed", err)
			}
			got, err := pair[1].ReceiveDatagram(ctx)
			if err != nil || !bytes.Equal(got, p) {
				t.Fatal("fragmented transfer failed", err)
			}
		}
	}
	if client.SendDatagram(make([]byte, 1403)) == nil {
		t.Fatal("oversized packet accepted")
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	if _, err := client.ReceiveDatagram(canceled); err == nil {
		t.Fatal("receive ignored cancellation")
	}
}
