package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"testing"
)

func TestHeartbeatEncodingAndProof(t *testing.T) {
	for _, kind := range []byte{DatagramTypePing, DatagramTypePong} {
		p := Heartbeat(kind, 0xf123456789abcde0)
		k, n, ok := ParseHeartbeat(p)
		if !ok || k != kind || n != 0xf123456789abcde0 {
			t.Fatal("heartbeat roundtrip failed")
		}
		for _, invalid := range [][]byte{p[:9], append(p, 0), Heartbeat(3, 1), append([]byte{2}, p[1:]...)} {
			if _, _, ok := ParseHeartbeat(invalid); ok {
				t.Fatal("accepted malformed heartbeat")
			}
		}
	}
	key := sha256.Sum256([]byte("credential"))
	m := Message{Type: TypeAuthRequest, Version: Version}
	legacy, _ := json.Marshal(m)
	if bytes.Contains(legacy, []byte("heartbeat")) {
		t.Fatal("legacy JSON changed")
	}
	m.Heartbeat = true
	challenge, _ := NewNonce()
	nonce, _ := NewNonce()
	m.Proof = AuthProof(key, ClientProofRole, challenge, nonce, m)
	if !VerifyAuthProof(key, ClientProofRole, challenge, nonce, m) {
		t.Fatal("valid proof rejected")
	}
	m.Heartbeat = false
	if VerifyAuthProof(key, ClientProofRole, challenge, nonce, m) {
		t.Fatal("capability mutation did not invalidate proof")
	}
}
