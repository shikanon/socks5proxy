package server

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
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
