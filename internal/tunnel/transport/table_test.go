package transport

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/shikanon/socks5proxy/internal/keytable"
)

func TestTableWireMapping(t *testing.T) {
	table, _, err := keytable.LoadOrCreate(filepath.Join(t.TempDir(), "table"), 16)
	if err != nil {
		t.Fatal(err)
	}
	raw, peer := pipeConn(t)
	conn := WithTable(raw, table)
	packet := make([]byte, 256)
	for i := range packet {
		packet[i] = byte(i)
	}
	done := make(chan error, 1)
	go func() {
		var header [2]byte
		if _, err := io.ReadFull(peer, header[:]); err != nil {
			done <- err
			return
		}
		wire := make([]byte, int(binary.BigEndian.Uint16(header[:])))
		_, err := io.ReadFull(peer, wire)
		if err == nil && (len(wire) != len(packet)+keytable.HeaderSize || bytes.Equal(wire[keytable.HeaderSize:], packet)) {
			t.Error("raw wire did not contain the mapped payload and date")
		}
		decoded, decodeErr := table.Decode(wire, time.Now())
		if decodeErr != nil || !bytes.Equal(decoded, packet) {
			t.Error("raw wire did not round trip", decodeErr)
		}
		if err == nil {
			err = writeFrame(peer, wire)
		}
		done <- err
	}()
	if err := conn.SendDatagram(packet); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := conn.ReceiveDatagram(ctx)
	if err != nil || !bytes.Equal(got, packet) {
		t.Fatal("receive failed", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if conn.SendDatagram(nil) == nil || conn.SendDatagram(make([]byte, maxTCPDatagram+1)) == nil {
		t.Fatal("table accepted invalid packet length")
	}
}

func TestTableRejectsInvalidEnvelope(t *testing.T) {
	table, _, err := keytable.LoadOrCreate(filepath.Join(t.TempDir(), "table"), 8)
	if err != nil {
		t.Fatal(err)
	}
	for _, payload := range [][]byte{[]byte{1}, table.Encode([]byte("packet"), time.Now().Add(-72*time.Hour))} {
		raw, peer := pipeConn(t)
		conn := WithTable(raw, table)
		go func() { _ = writeFrame(peer, payload) }()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_, err := conn.ReceiveDatagram(ctx)
		cancel()
		if err == nil || raw.Context().Err() == nil {
			t.Fatal("invalid table frame did not close connection")
		}
	}
}
