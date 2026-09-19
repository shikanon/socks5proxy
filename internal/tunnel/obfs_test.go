package tunnel

import (
	"bytes"
	"testing"
)

func TestTunnelObfuscatorsRoundTrip(t *testing.T) {
	for _, mode := range []string{"none", "simple", "random"} {
		t.Run(mode, func(t *testing.T) {
			cipher, err := NewObfuscator(mode, "0123456789abcdef0123456789abcdef")
			if err != nil {
				t.Fatal(err)
			}
			plain := []byte{0x45, 0x00, 0x00, 0x14, 0x7f, 0x00, 0x00, 0x01}
			packet := append([]byte(nil), plain...)
			if cipher == nil {
				if mode != "none" {
					t.Fatal("expected cipher")
				}
				return
			}
			if err := cipher.Encrypt(packet); err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(packet, plain) {
				t.Fatal("obfuscator did not transform payload")
			}
			if err := cipher.Decrypt(packet); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(packet, plain) {
				t.Fatalf("round trip mismatch: got %x want %x", packet, plain)
			}
		})
	}
}
