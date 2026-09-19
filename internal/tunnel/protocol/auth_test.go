package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestAuthProof(t *testing.T) {
	token := strings.Repeat("secret-token-", 4)
	key := sha256.Sum256([]byte(token))
	challenge, err := NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := NewNonce()
	if err != nil || nonce == challenge || !ValidNonce(nonce) {
		t.Fatal("nonces must be fresh 32-byte values", err)
	}
	request := Message{Type: TypeAuthRequest, Version: Version, ClientID: "desktop", Obfs: "random", Nonce: nonce}
	request.Proof = AuthProof(key, ClientProofRole, challenge, nonce, request)
	t.Run("valid_request_without_credentials_on_wire", func(t *testing.T) {
		if !VerifyAuthProof(key, ClientProofRole, challenge, nonce, request) {
			t.Fatal("valid proof rejected")
		}
		var wire bytes.Buffer
		if err := WriteMessage(&wire, request); err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(wire.Bytes(), []byte(token)) || bytes.Contains(wire.Bytes(), []byte(hex.EncodeToString(key[:]))) {
			t.Fatal("credential present on wire")
		}
		got, err := ReadMessage(&wire)
		if err != nil || got != request {
			t.Fatal("proof did not survive control serialization", err)
		}
	})
	for _, change := range []struct {
		name string
		edit func(*Message)
	}{
		{"client", func(m *Message) { m.ClientID = "another" }},
		{"obfs", func(m *Message) { m.Obfs = "none" }},
		{"nonce", func(m *Message) { m.Nonce = challenge }},
		{"version", func(m *Message) { m.Version++ }},
		{"token", func(m *Message) { m.Token = token }},
		{"invalid_hex", func(m *Message) { m.Proof = strings.Repeat("z", 64) }},
		{"short_proof", func(m *Message) { m.Proof = "00" }},
	} {
		t.Run(change.name, func(t *testing.T) {
			changed := request
			change.edit(&changed)
			if VerifyAuthProof(key, ClientProofRole, challenge, nonce, changed) {
				t.Fatal("tampered proof accepted")
			}
		})
	}
	t.Run("replay_wrong_key_and_role", func(t *testing.T) {
		fresh, _ := NewNonce()
		if VerifyAuthProof(key, ClientProofRole, fresh, nonce, request) ||
			VerifyAuthProof(sha256.Sum256([]byte("wrong")), ClientProofRole, challenge, nonce, request) ||
			VerifyAuthProof(key, ServerProofRole, challenge, nonce, request) {
			t.Fatal("replayed or incorrect credential accepted")
		}
	})
	response := Message{Type: TypeAuthResponse, Version: Version, ClientIPv4: "10.0.0.2", ServerIPv4: "10.0.0.1", DNSIPv4: "1.1.1.1", MTU: 1150, Obfs: "random", SessionID: "session"}
	response.Proof = AuthProof(key, ServerProofRole, challenge, nonce, response)
	t.Run("valid_response", func(t *testing.T) {
		if !VerifyAuthProof(key, ServerProofRole, challenge, nonce, response) {
			t.Fatal("valid response rejected")
		}
	})
	for _, change := range []struct {
		name string
		edit func(*Message)
	}{
		{"response_client_ip", func(m *Message) { m.ClientIPv4 = "10.0.0.3" }},
		{"response_server_ip", func(m *Message) { m.ServerIPv4 = "10.0.0.4" }},
		{"response_dns", func(m *Message) { m.DNSIPv4 = "8.8.8.8" }},
		{"response_mtu", func(m *Message) { m.MTU++ }},
		{"response_session", func(m *Message) { m.SessionID = "other" }},
		{"response_obfs", func(m *Message) { m.Obfs = "simple" }},
	} {
		t.Run(change.name, func(t *testing.T) {
			changed := response
			change.edit(&changed)
			if VerifyAuthProof(key, ServerProofRole, challenge, nonce, changed) {
				t.Fatal("changed response accepted")
			}
		})
	}
}

func TestNonceAndChallenge(t *testing.T) {
	for _, invalid := range []string{"", "00", strings.Repeat("z", 64), strings.Repeat("00", 33)} {
		if ValidNonce(invalid) {
			t.Fatalf("accepted invalid nonce %q", invalid)
		}
	}
	nonce, _ := NewNonce()
	challenge := Message{Type: TypeAuthChallenge, Version: Version, Nonce: nonce}
	var buf bytes.Buffer
	if err := WriteMessage(&buf, challenge); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadMessage(&buf); err != nil || got != challenge {
		t.Fatal("challenge round trip failed", err)
	}
}
