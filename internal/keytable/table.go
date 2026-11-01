// Package keytable implements a daily substitution cipher for learning.
// Substitution does not provide confidentiality, integrity or replay protection.
package keytable

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	DefaultFile        = "token-table.json"
	DefaultTokenLength = 16
	TokenCount         = 256
	HeaderSize         = 8
	secondsPerDay      = 86400
	alphabet           = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

type document struct {
	Version int      `json:"version"`
	Tokens  []string `json:"tokens"`
}

type mapping struct {
	encode [256]byte
	decode [256]byte
}

// Table is immutable apart from a bounded cache and is safe for concurrent use.
type Table struct {
	key   [sha256.Size]byte
	mu    sync.Mutex
	cache map[int64]mapping
}

func Parse(data []byte) (*Table, error) {
	if len(data) > 64*1024 {
		return nil, errors.New("token table exceeds 64 KiB")
	}
	var doc document
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode token table: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, errors.New("token table must contain exactly one JSON document")
	}
	if doc.Version != 1 || len(doc.Tokens) != TokenCount {
		return nil, errors.New("token table requires version 1 and exactly 256 tokens")
	}
	seen := make(map[string]bool, TokenCount)
	for _, token := range doc.Tokens {
		if len(token) < 8 || len(token) > 16 || strings.Trim(token, alphabet) != "" {
			return nil, errors.New("table tokens must be 8–16 ASCII letters or digits")
		}
		if seen[token] {
			return nil, errors.New("token table contains duplicate tokens")
		}
		seen[token] = true
	}
	canonical, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	key := sha256.Sum256(append([]byte("socks5proxy-token-table/1\x00"), canonical...))
	return &Table{key: key, cache: make(map[int64]mapping)}, nil
}

func Load(path string) (*Table, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open token table: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("token table must be a regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("token table must not be accessible by group or others")
	}
	data, err := io.ReadAll(io.LimitReader(file, 64*1024+1))
	if err != nil {
		return nil, fmt.Errorf("read token table: %w", err)
	}
	return Parse(data)
}

// LoadOrCreate persists a table only when absent, retaining it across restarts.
// A hard link atomically publishes the complete file without overwriting it.
func LoadOrCreate(path string, tokenLength int) (*Table, bool, error) {
	if tokenLength < 8 || tokenLength > 16 {
		return nil, false, errors.New("table token length must be between 8 and 16")
	}
	if table, err := Load(path); err == nil {
		return table, false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, false, err
	}
	doc := document{Version: 1, Tokens: make([]string, 0, TokenCount)}
	seen := make(map[string]bool, TokenCount)
	for len(doc.Tokens) < TokenCount {
		token, err := randomToken(tokenLength)
		if err != nil {
			return nil, false, err
		}
		if !seen[token] {
			seen[token] = true
			doc.Tokens = append(doc.Tokens, token)
		}
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, false, err
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, false, err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".token-table-*")
	if err != nil {
		return nil, false, err
	}
	defer os.Remove(temp.Name())
	defer temp.Close()
	if _, err := temp.Write(data); err != nil {
		return nil, false, err
	}
	if err := temp.Sync(); err != nil {
		return nil, false, err
	}
	if err := temp.Close(); err != nil {
		return nil, false, err
	}
	if err := os.Link(temp.Name(), path); err != nil {
		if errors.Is(err, os.ErrExist) {
			table, loadErr := Load(path)
			return table, false, loadErr
		}
		return nil, false, fmt.Errorf("publish token table: %w", err)
	}
	table, err := Parse(data)
	return table, true, err
}

func randomToken(length int) (string, error) {
	out := make([]byte, 0, length)
	for len(out) < length {
		var buf [32]byte
		if _, err := rand.Read(buf[:]); err != nil {
			return "", err
		}
		for _, v := range buf {
			// Reject the uneven tail instead of biasing the base-62 alphabet.
			if v >= 248 {
				continue
			}
			out = append(out, alphabet[int(v)%len(alphabet)])
			if len(out) == length {
				break
			}
		}
	}
	return string(out), nil
}

// Credential feeds the existing TCP challenge protocol; never send it directly.
func (t *Table) Credential() string {
	mac := hmac.New(sha256.New, t.key[:])
	_, _ = mac.Write([]byte("socks5proxy-token-table-auth/1"))
	return hex.EncodeToString(mac.Sum(nil))
}

func dayTimestamp(now time.Time) int64 {
	now = now.UTC()
	return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC).Unix()
}

func (t *Table) daily(day int64) mapping {
	t.mu.Lock()
	defer t.mu.Unlock()
	if result, ok := t.cache[day]; ok {
		return result
	}
	var result mapping
	for i := range result.encode {
		result.encode[i] = byte(i)
	}
	// Fisher–Yates uses a deterministic HMAC byte stream seeded by the full
	// table and UTC midnight timestamp. This is still only a substitution.
	var input [16]byte
	binary.BigEndian.PutUint64(input[:8], uint64(day))
	var block []byte
	var counter uint64
	next := func() uint32 {
		if len(block) < 4 {
			binary.BigEndian.PutUint64(input[8:], counter)
			counter++
			mac := hmac.New(sha256.New, t.key[:])
			_, _ = mac.Write([]byte("socks5proxy-token-table-map/1\x00"))
			_, _ = mac.Write(input[:])
			block = mac.Sum(nil)
		}
		v := binary.BigEndian.Uint32(block[:4])
		block = block[4:]
		return v
	}
	for i := 255; i > 0; i-- {
		n := uint64(i + 1)
		limit := uint64(1)<<32 - (uint64(1)<<32)%n
		v := uint64(next())
		for v >= limit {
			v = uint64(next())
		}
		j := int(v % n)
		result.encode[i], result.encode[j] = result.encode[j], result.encode[i]
	}
	for i, v := range result.encode {
		result.decode[v] = byte(i)
	}
	if len(t.cache) >= 3 {
		clear(t.cache)
	}
	t.cache[day] = result
	return result
}

func (t *Table) Encode(payload []byte, now time.Time) []byte {
	day := dayTimestamp(now)
	keys := t.daily(day)
	out := make([]byte, HeaderSize+len(payload))
	binary.BigEndian.PutUint64(out[:HeaderSize], uint64(day))
	for i, v := range payload {
		out[HeaderSize+i] = keys.encode[v]
	}
	return out
}

// Decode accepts adjacent UTC days to handle midnight and small clock skew.
// The timestamp is public and is not a MAC or replay-prevention mechanism.
func (t *Table) Decode(payload []byte, now time.Time) ([]byte, error) {
	if len(payload) <= HeaderSize {
		return nil, errors.New("daily table frame is too short")
	}
	day := int64(binary.BigEndian.Uint64(payload[:HeaderSize]))
	today := dayTimestamp(now)
	if day%secondsPerDay != 0 || day < today-secondsPerDay || day > today+secondsPerDay {
		return nil, errors.New("table frame date must be yesterday, today or tomorrow in UTC")
	}
	keys := t.daily(day)
	out := make([]byte, len(payload)-HeaderSize)
	for i, v := range payload[HeaderSize:] {
		out[i] = keys.decode[v]
	}
	return out, nil
}
