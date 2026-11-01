package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"net/netip"
	"testing"
)

func ipv6Packet(size int) []byte {
	p := make([]byte, size)
	p[0], p[6], p[7] = 0x60, 44, 64 // IPv6 fragment headers are valid payloads.
	binary.BigEndian.PutUint16(p[4:6], uint16(size-40))
	src, dst := netip.MustParseAddr("fd00:5:5::2").As16(), netip.MustParseAddr("2001:db8::1").As16()
	copy(p[8:24], src[:])
	copy(p[24:40], dst[:])
	return p
}

type ipv6Cipher struct{}

func (ipv6Cipher) Encrypt(p []byte) error {
	for i := range p {
		p[i] ^= 0xa5
	}
	return nil
}
func (c ipv6Cipher) Decrypt(p []byte) error { return c.Encrypt(p) }

func TestIPv6Datagram(t *testing.T) {
	for _, size := range []int{40, 1280, 1400} {
		p := ipv6Packet(size)
		encoded, info, err := EncodeDatagram(p, size, ipv6Cipher{})
		if err != nil {
			t.Fatal(err)
		}
		if encoded[1] != DatagramTypeIPv6 || info.Source.String() != "fd00:5:5::2" {
			t.Fatal("wrong IPv6 framing or address", info)
		}
		decoded, got, err := DecodeDatagram(encoded, size, ipv6Cipher{})
		if err != nil || !bytes.Equal(decoded, p) || got != info {
			t.Fatal("IPv6 round trip failed", err)
		}
		encoded[1] = DatagramTypeIPv4
		if _, _, err := DecodeDatagram(encoded, size, ipv6Cipher{}); err == nil {
			t.Fatal("mismatched family accepted")
		}
	}
	for _, p := range [][]byte{nil, {0x60}, ipv6Packet(1280)[:1279]} {
		if _, err := ValidateIPv6(p, 1280); err == nil {
			t.Fatal("short or inconsistent IPv6 accepted")
		}
	}
	if _, err := ValidateIPv6(ipv6Packet(1280), 1150); err == nil {
		t.Fatal("over MTU packet accepted")
	}
	p := ipv6Packet(1280)
	p[0] = 0x45
	if _, err := ValidateIPv6(p, 1280); err == nil {
		t.Fatal("wrong IP version accepted")
	}
}

func TestIPv6Negotiation(t *testing.T) {
	valid := Message{IPv6: true, ClientIPv6: "fd00:5:5::2", ServerIPv6: "fd00:5:5::1", DNSIPv6: "2606:4700:4700::1111", MTU: 1280}
	if _, _, _, err := ValidateIPv6Parameters(valid, true); err != nil {
		t.Fatal(err)
	}
	for _, edit := range []func(*Message){
		func(m *Message) { m.IPv6 = false },
		func(m *Message) { m.ClientIPv6 = "" },
		func(m *Message) { m.ClientIPv6 = "::" },
		func(m *Message) { m.ClientIPv6 = "fe80::1" },
		func(m *Message) { m.ServerIPv6 = m.ClientIPv6 },
		func(m *Message) { m.DNSIPv6 = "1.1.1.1" },
		func(m *Message) { m.MTU = 1150 },
	} {
		m := valid
		edit(&m)
		if _, _, _, err := ValidateIPv6Parameters(m, true); err == nil {
			t.Fatal("invalid IPv6 parameters accepted", m)
		}
	}
	if _, _, _, err := ValidateIPv6Parameters(valid, false); err == nil {
		t.Fatal("unsolicited IPv6 accepted")
	}
	if _, _, _, err := ValidateIPv6Parameters(Message{}, true); err == nil {
		t.Fatal("unsupported IPv6 accepted")
	}
	if _, _, _, err := ValidateIPv6Parameters(Message{}, false); err != nil {
		t.Fatal("legacy response rejected", err)
	}
}

func TestIPv6ProofFields(t *testing.T) {
	key := sha256.Sum256([]byte("credential"))
	challenge, _ := NewNonce()
	nonce, _ := NewNonce()
	m := Message{Type: TypeAuthResponse, Version: Version, IPv6: true, ClientIPv6: "fd00::2", ServerIPv6: "fd00::1", DNSIPv6: "2001:db8::53", MTU: 1280}
	m.Proof = AuthProof(key, ServerProofRole, challenge, nonce, m)
	for _, edit := range []func(*Message){
		func(m *Message) { m.IPv6 = false },
		func(m *Message) { m.ClientIPv6 = "fd00::3" },
		func(m *Message) { m.ServerIPv6 = "fd00::4" },
		func(m *Message) { m.DNSIPv6 = "" },
	} {
		changed := m
		edit(&changed)
		if VerifyAuthProof(key, ServerProofRole, challenge, nonce, changed) {
			t.Fatal("tampered IPv6 negotiation accepted")
		}
	}
}
