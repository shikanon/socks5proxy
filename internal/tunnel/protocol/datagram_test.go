package protocol

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

type xorCipher byte

func (c xorCipher) Encrypt(b []byte) error {
	for i := range b {
		b[i] ^= byte(c)
	}
	return nil
}

func (c xorCipher) Decrypt(b []byte) error {
	return c.Encrypt(b)
}

func ipv4Packet(src, dst [4]byte, payload []byte) []byte {
	packet := make([]byte, 20+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = 17
	copy(packet[12:16], src[:])
	copy(packet[16:20], dst[:])
	copy(packet[20:], payload)
	return packet
}

func TestDatagramRoundTripWithObfuscation(t *testing.T) {
	raw := ipv4Packet([4]byte{10, 0, 0, 2}, [4]byte{1, 1, 1, 1}, []byte("dns"))
	encoded, info, err := EncodeDatagram(raw, 1280, xorCipher(0x5a))
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded[2:]) == string(raw) {
		t.Fatal("payload was not transformed")
	}
	if info.Source != netip.MustParseAddr("10.0.0.2") {
		t.Fatalf("unexpected source %s", info.Source)
	}
	decoded, decodedInfo, err := DecodeDatagram(encoded, 1280, xorCipher(0x5a))
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != string(raw) {
		t.Fatalf("packet mismatch: got %x want %x", decoded, raw)
	}
	if decodedInfo.Destination != netip.MustParseAddr("1.1.1.1") {
		t.Fatalf("unexpected destination %s", decodedInfo.Destination)
	}
}

func TestValidateIPv4RejectsMalformedPackets(t *testing.T) {
	valid := ipv4Packet([4]byte{10, 0, 0, 2}, [4]byte{1, 1, 1, 1}, nil)
	tests := []struct {
		name   string
		packet []byte
		mtu    int
	}{
		{name: "short", packet: []byte{0x45}, mtu: 1280},
		{name: "ipv6", packet: append([]byte{0x60}, valid[1:]...), mtu: 1280},
		{name: "bad length", packet: append(valid, 0), mtu: 1280},
		{name: "over mtu", packet: valid, mtu: 19},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ValidateIPv4(tt.packet, tt.mtu); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}
