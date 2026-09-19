package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

const (
	DatagramTypeIPv4  = 1
	datagramHeaderLen = 2
)

type Cipher interface {
	Encrypt([]byte) error
	Decrypt([]byte) error
}

type PacketInfo struct {
	Source      netip.Addr
	Destination netip.Addr
	Length      int
}

func EncodeDatagram(packet []byte, mtu int, cipher Cipher) ([]byte, PacketInfo, error) {
	info, err := ValidateIPv4(packet, mtu)
	if err != nil {
		return nil, PacketInfo{}, err
	}
	out := make([]byte, datagramHeaderLen+len(packet))
	out[0] = Version
	out[1] = DatagramTypeIPv4
	copy(out[datagramHeaderLen:], packet)
	if cipher != nil {
		if err := cipher.Encrypt(out[datagramHeaderLen:]); err != nil {
			return nil, PacketInfo{}, fmt.Errorf("obfuscate datagram: %w", err)
		}
	}
	return out, info, nil
}

func DecodeDatagram(datagram []byte, mtu int, cipher Cipher) ([]byte, PacketInfo, error) {
	if len(datagram) <= datagramHeaderLen {
		return nil, PacketInfo{}, errors.New("datagram is too short")
	}
	if datagram[0] != Version {
		return nil, PacketInfo{}, fmt.Errorf("unsupported datagram version %d", datagram[0])
	}
	if datagram[1] != DatagramTypeIPv4 {
		return nil, PacketInfo{}, fmt.Errorf("unsupported datagram type %d", datagram[1])
	}
	packet := append([]byte(nil), datagram[datagramHeaderLen:]...)
	if cipher != nil {
		if err := cipher.Decrypt(packet); err != nil {
			return nil, PacketInfo{}, fmt.Errorf("deobfuscate datagram: %w", err)
		}
	}
	info, err := ValidateIPv4(packet, mtu)
	if err != nil {
		return nil, PacketInfo{}, err
	}
	return packet, info, nil
}

func ValidateIPv4(packet []byte, mtu int) (PacketInfo, error) {
	if len(packet) < 20 {
		return PacketInfo{}, errors.New("IPv4 packet is too short")
	}
	if packet[0]>>4 != 4 {
		return PacketInfo{}, errors.New("packet is not IPv4")
	}
	headerLen := int(packet[0]&0x0f) * 4
	if headerLen < 20 || headerLen > len(packet) {
		return PacketInfo{}, errors.New("invalid IPv4 header length")
	}
	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLen != len(packet) {
		return PacketInfo{}, fmt.Errorf("IPv4 total length %d does not match packet length %d", totalLen, len(packet))
	}
	if mtu > 0 && totalLen > mtu {
		return PacketInfo{}, fmt.Errorf("IPv4 packet length %d exceeds MTU %d", totalLen, mtu)
	}
	var src, dst [4]byte
	copy(src[:], packet[12:16])
	copy(dst[:], packet[16:20])
	return PacketInfo{
		Source:      netip.AddrFrom4(src),
		Destination: netip.AddrFrom4(dst),
		Length:      totalLen,
	}, nil
}
