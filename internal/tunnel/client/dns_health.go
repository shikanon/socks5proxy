package client

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/shikanon/socks5proxy/internal/tunnel"
	"github.com/shikanon/socks5proxy/internal/tunnel/protocol"
	"golang.org/x/net/dns/dnsmessage"
)

type dnsRequest struct{ sent time.Time }
type dnsPath struct {
	client, server netip.Addr
	question       dnsmessage.Question
	pending        map[uint32]dnsRequest
	last           time.Time
	verified       bool
}

func newDNSPaths(r protocol.Message, name string) ([]dnsPath, error) {
	if name == "" {
		name = tunnel.DefaultHealthDNSName
	}
	if err := tunnel.ValidateHealthDNSName(name); err != nil {
		return nil, err
	}
	qname, err := dnsmessage.NewName(strings.TrimSuffix(name, ".") + ".")
	if err != nil {
		return nil, err
	}
	var paths []dnsPath
	for _, pair := range [][2]string{{r.ClientIPv4, r.DNSIPv4}, {r.ClientIPv6, r.DNSIPv6}} {
		if pair[0] == "" && len(paths) > 0 {
			continue
		}
		client, e1 := netip.ParseAddr(pair[0])
		server, e2 := netip.ParseAddr(pair[1])
		if e1 != nil || e2 != nil || client.Is4() != server.Is4() || client.IsUnspecified() || server.IsUnspecified() {
			return nil, errors.New("invalid tunnel DNS probe addresses")
		}
		kind := dnsmessage.TypeA
		if client.Is6() {
			kind = dnsmessage.TypeAAAA
		}
		paths = append(paths, dnsPath{client: client, server: server,
			question: dnsmessage.Question{Name: qname, Type: kind, Class: dnsmessage.ClassINET},
			pending:  make(map[uint32]dnsRequest), last: time.Now()})
	}
	return paths, nil
}

// Called under the monitor lock. Every request has a fresh DNS ID and UDP port.
func (p *dnsPath) request(now time.Time, timeout time.Duration) []byte {
	for key, req := range p.pending {
		if now.Sub(req.sent) >= timeout {
			delete(p.pending, key)
		}
	}
	nonce := randomNonce()
	id, port := uint16(nonce), uint16(49152+(nonce>>16)%16384)
	key := uint32(port)<<16 | uint32(id)
	p.pending[key] = dnsRequest{sent: now}
	message := dnsmessage.Message{Header: dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{p.question}}
	body, err := message.Pack()
	if err != nil {
		panic(err) // The name and question were validated at construction.
	}
	return udpPacket(p.client, p.server, port, 53, body)
}

// Match the complete socket tuple, ID and question before consuming a reply.
// An owned SERVFAIL, truncated or empty answer is consumed but not healthy.
func (p *dnsPath) reply(packet []byte, now time.Time, timeout time.Duration) bool {
	info, err := protocol.ValidatePacket(packet, 0)
	if err != nil || info.Source != p.server || info.Destination != p.client {
		return false
	}
	udp, ok := packetUDP(packet)
	if !ok || binary.BigEndian.Uint16(udp[:2]) != 53 {
		return false
	}
	var message dnsmessage.Message
	if err := message.Unpack(udp[8:]); err != nil || len(message.Questions) != 1 {
		return false
	}
	key := uint32(binary.BigEndian.Uint16(udp[2:4]))<<16 | uint32(message.ID)
	req, ok := p.pending[key]
	q := message.Questions[0]
	if !ok || now.Sub(req.sent) >= timeout || !message.Response || message.OpCode != 0 ||
		q.Type != p.question.Type || q.Class != p.question.Class || !strings.EqualFold(q.Name.String(), p.question.Name.String()) {
		return false
	}
	delete(p.pending, key)
	if !message.Truncated && message.RCode == dnsmessage.RCodeSuccess {
		names := map[string]bool{strings.ToLower(q.Name.String()): true}
		for range message.Answers {
			for _, answer := range message.Answers {
				alias, ok := answer.Body.(*dnsmessage.CNAMEResource)
				if ok && answer.Header.Class == q.Class && names[strings.ToLower(answer.Header.Name.String())] {
					names[strings.ToLower(alias.CNAME.String())] = true
				}
			}
		}
		for _, answer := range message.Answers {
			if answer.Header.Type == q.Type && answer.Header.Class == q.Class && names[strings.ToLower(answer.Header.Name.String())] {
				p.last, p.verified = now, true
				break
			}
		}
	}
	return true
}

func checksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data))
		data = data[2:]
	}
	if len(data) != 0 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + sum>>16
	}
	return ^uint16(sum)
}

func udpPseudo(packet []byte, udp []byte) []byte {
	var pseudo []byte
	if packet[0]>>4 == 4 {
		pseudo = append(pseudo, packet[12:20]...)
		pseudo = append(pseudo, 0, 17, byte(len(udp)>>8), byte(len(udp)))
	} else {
		pseudo = append(pseudo, packet[8:40]...)
		pseudo = append(pseudo, 0, 0, byte(len(udp)>>8), byte(len(udp)), 0, 0, 0, 17)
	}
	return append(pseudo, udp...)
}

func udpPacket(src, dst netip.Addr, sport, dport uint16, body []byte) []byte {
	header := 20
	if src.Is6() {
		header = 40
	}
	packet := make([]byte, header+8+len(body))
	if src.Is4() {
		packet[0], packet[8], packet[9] = 0x45, 64, 17
		binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
		a, b := src.As4(), dst.As4()
		copy(packet[12:16], a[:])
		copy(packet[16:20], b[:])
		binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:20]))
	} else {
		packet[0], packet[6], packet[7] = 0x60, 17, 64
		binary.BigEndian.PutUint16(packet[4:6], uint16(len(packet)-40))
		a, b := src.As16(), dst.As16()
		copy(packet[8:24], a[:])
		copy(packet[24:40], b[:])
	}
	udp := packet[header:]
	binary.BigEndian.PutUint16(udp[:2], sport)
	binary.BigEndian.PutUint16(udp[2:4], dport)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], body)
	sum := checksum(udpPseudo(packet, udp))
	if sum == 0 {
		sum = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:8], sum)
	return packet
}

func packetUDP(packet []byte) ([]byte, bool) {
	header := 40
	switch packet[0] >> 4 {
	case 4:
		header = int(packet[0]&15) * 4
		if packet[9] != 17 || binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 || checksum(packet[:header]) != 0 {
			return nil, false
		}
	case 6:
		if packet[6] != 17 {
			return nil, false
		}
	default:
		return nil, false
	}
	if len(packet) < header+8 {
		return nil, false
	}
	udp := packet[header:]
	if int(binary.BigEndian.Uint16(udp[4:6])) != len(udp) {
		return nil, false
	}
	if binary.BigEndian.Uint16(udp[6:8]) == 0 {
		return udp, packet[0]>>4 == 4
	}
	return udp, checksum(udpPseudo(packet, udp)) == 0
}
