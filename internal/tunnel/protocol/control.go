package protocol

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	Version        = 1
	ALPN           = "socks5proxy-tunnel/1"
	MaxControlSize = 64 * 1024

	TypeAuthRequest   = "auth_request"
	TypeAuthResponse  = "auth_response"
	TypeAuthChallenge = "auth_challenge"
	TypeError         = "error"
)

type Message struct {
	Type       string `json:"type"`
	Version    int    `json:"version"`
	ClientID   string `json:"client_id,omitempty"`
	Token      string `json:"token,omitempty"`
	Nonce      string `json:"nonce,omitempty"`
	Proof      string `json:"proof,omitempty"`
	Obfs       string `json:"obfs,omitempty"`
	SessionID  string `json:"session_id,omitempty"`
	ClientIPv4 string `json:"client_ipv4,omitempty"`
	ServerIPv4 string `json:"server_ipv4,omitempty"`
	MTU        int    `json:"mtu,omitempty"`
	DNSIPv4    string `json:"dns_ipv4,omitempty"`
	Error      string `json:"error,omitempty"`
}

func WriteMessage(w io.Writer, msg Message) error {
	payload, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	if len(payload) > MaxControlSize {
		return errors.New("control message too large")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if err := writeFull(w, header[:]); err != nil {
		return err
	}
	return writeFull(w, payload)
}

func ReadMessage(r io.Reader) (Message, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return Message{}, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > MaxControlSize {
		return Message{}, fmt.Errorf("invalid control message size %d", size)
	}
	payload := make([]byte, int(size))
	if _, err := io.ReadFull(r, payload); err != nil {
		return Message{}, err
	}
	var msg Message
	if err := json.Unmarshal(payload, &msg); err != nil {
		return Message{}, fmt.Errorf("decode control message: %w", err)
	}
	if msg.Version != Version {
		return Message{}, fmt.Errorf("unsupported tunnel protocol version %d", msg.Version)
	}
	switch msg.Type {
	case TypeAuthRequest, TypeAuthResponse, TypeAuthChallenge, TypeError:
	default:
		return Message{}, fmt.Errorf("unsupported control message type %q", msg.Type)
	}
	return msg, nil
}

func writeFull(w io.Writer, payload []byte) error {
	for len(payload) > 0 {
		n, err := w.Write(payload)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		payload = payload[n:]
	}
	return nil
}
