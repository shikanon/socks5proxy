package protocol

import (
	"bytes"
	"io"
	"testing"
)

type shortWriter struct {
	bytes.Buffer
}

func (w *shortWriter) Write(p []byte) (int, error) {
	if len(p) > 3 {
		p = p[:3]
	}
	return w.Buffer.Write(p)
}

type chunkReader struct {
	data []byte
}

func (r *chunkReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := 2
	if n > len(r.data) {
		n = len(r.data)
	}
	if n > len(p) {
		n = len(p)
	}
	copy(p, r.data[:n])
	r.data = r.data[n:]
	return n, nil
}

func TestControlMessageRoundTripWithShortIO(t *testing.T) {
	want := Message{
		Type:     TypeAuthRequest,
		Version:  Version,
		ClientID: "desktop",
		Token:    "secret",
		Obfs:     "random",
	}
	var writer shortWriter
	if err := WriteMessage(&writer, want); err != nil {
		t.Fatal(err)
	}
	got, err := ReadMessage(&chunkReader{data: writer.Bytes()})
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("message mismatch: got %#v want %#v", got, want)
	}
}

func TestReadMessageRejectsUnknownVersion(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteMessage(&buf, Message{Type: TypeError, Version: 2, Error: "x"}); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadMessage(&buf); err == nil {
		t.Fatal("expected unsupported version error")
	}
}

func TestReadMessageRejectsOversizedLength(t *testing.T) {
	header := []byte{0x00, 0x01, 0x00, 0x01}
	if _, err := ReadMessage(bytes.NewReader(header)); err == nil {
		t.Fatal("expected size error")
	}
}

func TestReadMessageRejectsUnknownType(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteMessage(&buf, Message{Type: "unknown", Version: Version}); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadMessage(&buf); err == nil {
		t.Fatal("expected unsupported type error")
	}
}

func TestWriteMessageRejectsOversizedPayload(t *testing.T) {
	message := Message{
		Type:     TypeAuthRequest,
		Version:  Version,
		ClientID: string(bytes.Repeat([]byte{'a'}, MaxControlSize)),
	}
	if err := WriteMessage(io.Discard, message); err == nil {
		t.Fatal("expected oversized message error")
	}
}
