package server

import (
	"bufio"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
)

type TokenStore struct {
	hashes map[string][sha256.Size]byte
}

func LoadTokenStore(path string) (*TokenStore, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat token file: %w", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("server token file must not be accessible by group or others")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open token file: %w", err)
	}
	defer file.Close()

	store := &TokenStore{hashes: make(map[string][sha256.Size]byte)}
	scanner := bufio.NewScanner(file)
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		clientID, hashText, ok := strings.Cut(line, ":")
		clientID = strings.TrimSpace(clientID)
		hashText = strings.TrimSpace(hashText)
		if !ok || clientID == "" {
			return nil, fmt.Errorf("invalid token entry on line %d", lineNo)
		}
		if _, exists := store.hashes[clientID]; exists {
			return nil, fmt.Errorf("duplicate client ID %q", clientID)
		}
		decoded, err := hex.DecodeString(hashText)
		if err != nil || len(decoded) != sha256.Size {
			return nil, fmt.Errorf("invalid SHA-256 token digest on line %d", lineNo)
		}
		var digest [sha256.Size]byte
		copy(digest[:], decoded)
		store.hashes[clientID] = digest
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read token file: %w", err)
	}
	if len(store.hashes) == 0 {
		return nil, errors.New("token file contains no clients")
	}
	return store, nil
}

func (s *TokenStore) Authenticate(clientID, token string) bool {
	expected, ok := s.hashes[clientID]
	actual := sha256.Sum256([]byte(token))
	if !ok {
		var zero [sha256.Size]byte
		subtle.ConstantTimeCompare(zero[:], actual[:])
		return false
	}
	return subtle.ConstantTimeCompare(expected[:], actual[:]) == 1
}

func (s *TokenStore) ClientIDs() []string {
	ids := make([]string, 0, len(s.hashes))
	for clientID := range s.hashes {
		ids = append(ids, clientID)
	}
	sort.Strings(ids)
	return ids
}
