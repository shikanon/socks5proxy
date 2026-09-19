package server

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/shikanon/socks5proxy/internal/tunnel/protocol"
)

func TestTokenStoreAuthentication(t *testing.T) {
	token := "0123456789abcdef0123456789abcdef"
	digest := sha256.Sum256([]byte(token))
	path := filepath.Join(t.TempDir(), "tokens")
	content := "# clients\n desktop:" + hex.EncodeToString(digest[:]) + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := LoadTokenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if !store.Authenticate("desktop", token) {
		t.Fatal("valid token was rejected")
	}
	if store.Authenticate("desktop", token+"x") {
		t.Fatal("invalid token was accepted")
	}
	if store.Authenticate("unknown", token) {
		t.Fatal("unknown client was accepted")
	}
}

func TestTokenStoreRejectsDuplicateClient(t *testing.T) {
	digest := sha256.Sum256([]byte("0123456789abcdef0123456789abcdef"))
	entry := "desktop:" + hex.EncodeToString(digest[:]) + "\n"
	path := filepath.Join(t.TempDir(), "tokens")
	if err := os.WriteFile(path, []byte(entry+entry), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTokenStore(path); err == nil {
		t.Fatal("expected duplicate client error")
	}
}

func TestTokenStoreChallengeAuthentication(t *testing.T) {
	key := sha256.Sum256([]byte("0123456789abcdef0123456789abcdef"))
	store := &TokenStore{hashes: map[string][sha256.Size]byte{"desktop": key}}
	challenge, _ := protocol.NewNonce()
	nonce, _ := protocol.NewNonce()
	for _, name := range []string{"valid", "unknown", "wrong_token", "plaintext_token", "wrong_type"} {
		t.Run(name, func(t *testing.T) {
			request := protocol.Message{Type: protocol.TypeAuthRequest, Version: protocol.Version, ClientID: "desktop", Nonce: nonce, Obfs: "random"}
			proofKey := key
			switch name {
			case "unknown":
				request.ClientID = "unknown"
			case "wrong_token":
				proofKey = sha256.Sum256([]byte("wrong"))
			case "plaintext_token":
				request.Token = "credential-must-not-be-transmitted"
			case "wrong_type":
				request.Type = protocol.TypeAuthResponse
			}
			request.Proof = protocol.AuthProof(proofKey, protocol.ClientProofRole, challenge, nonce, request)
			got, valid := store.AuthenticateProof(challenge, request)
			if valid != (name == "valid") || (valid && got != key) {
				t.Fatal("unexpected proof authentication result")
			}
		})
	}
}
