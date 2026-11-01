package protocol

import "encoding/binary"

const (
	DatagramTypePing = 4
	DatagramTypePong = 5
)

// Heartbeat is a control datagram on an already authenticated data connection.
func Heartbeat(kind byte, nonce uint64) []byte {
	p := make([]byte, 10)
	p[0], p[1] = Version, kind
	binary.BigEndian.PutUint64(p[2:], nonce)
	return p
}

func ParseHeartbeat(p []byte) (kind byte, nonce uint64, ok bool) {
	if len(p) != 10 || p[0] != Version || (p[1] != DatagramTypePing && p[1] != DatagramTypePong) {
		return 0, 0, false
	}
	return p[1], binary.BigEndian.Uint64(p[2:]), true
}
