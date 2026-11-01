package keytable

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestTablePersistence(t *testing.T) {
	for _, length := range []int{8, 12, 16} {
		path := filepath.Join(t.TempDir(), "private", "table.json")
		first, created, err := LoadOrCreate(path, length)
		if err != nil || !created {
			t.Fatal("generate table", created, err)
		}
		data, _ := os.ReadFile(path)
		var doc document
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatal(err)
		}
		for _, token := range doc.Tokens {
			if len(token) != length {
				t.Fatal("wrong token length")
			}
		}
		second, created, err := LoadOrCreate(path, length)
		after, _ := os.ReadFile(path)
		if err != nil || created || first.Credential() != second.Credential() || !bytes.Equal(data, after) {
			t.Fatal("restart replaced the table", err)
		}
		info, _ := os.Stat(path)
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
			t.Fatal("table is not private")
		}
	}
	for _, length := range []int{7, 17} {
		if _, _, err := LoadOrCreate(filepath.Join(t.TempDir(), "table"), length); err == nil {
			t.Fatal("invalid token length accepted")
		}
	}
}

func TestTableRejectsInvalidFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "table")
	_, _, err := LoadOrCreate(path, 8)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	var original document
	_ = json.Unmarshal(data, &original)
	for _, scenario := range []string{"version", "count", "duplicate", "short", "long", "unicode", "trailing", "unknown", "oversized"} {
		t.Run(scenario, func(t *testing.T) {
			doc := document{Version: 1, Tokens: append([]string(nil), original.Tokens...)}
			switch scenario {
			case "version":
				doc.Version = 2
			case "count":
				doc.Tokens = doc.Tokens[:255]
			case "duplicate":
				doc.Tokens[1] = doc.Tokens[0]
			case "short":
				doc.Tokens[1] = "abc"
			case "long":
				doc.Tokens[1] = "01234567890123456"
			case "unicode":
				doc.Tokens[1] = "令牌abcdef"
			}
			bad, _ := json.Marshal(doc)
			switch scenario {
			case "trailing":
				bad = append(bad, []byte("{}")...)
			case "unknown":
				bad = append([]byte(`{"extra":1,`), bad[1:]...)
			case "oversized":
				bad = bytes.Repeat([]byte(" "), 64*1024+1)
			}
			if _, err := Parse(bad); err == nil {
				t.Fatal("invalid table accepted")
			}
		})
	}
	_ = os.WriteFile(path, []byte("invalid"), 0o600)
	if _, _, err := LoadOrCreate(path, 8); err == nil {
		t.Fatal("malformed existing table silently replaced")
	}
	_ = os.WriteFile(path, data, 0o600)
	if runtime.GOOS != "windows" {
		_ = os.Chmod(path, 0o644)
		if _, err := Load(path); err == nil {
			t.Fatal("public table accepted")
		}
	}
}

func TestDailyMappingAndMidnight(t *testing.T) {
	table, _, err := LoadOrCreate(filepath.Join(t.TempDir(), "table"), 16)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 24, 23, 59, 59, 0, time.UTC)
	packet := make([]byte, 256)
	for i := range packet {
		packet[i] = byte(i)
	}
	encoded := table.Encode(packet, now)
	if int64(binary.BigEndian.Uint64(encoded)) != dayTimestamp(now) || bytes.Equal(encoded[HeaderSize:], packet) {
		t.Fatal("incorrect date or unmapped payload")
	}
	seen := map[byte]bool{}
	for _, v := range encoded[HeaderSize:] {
		seen[v] = true
	}
	if len(seen) != 256 {
		t.Fatal("mapping is not bijective")
	}
	for _, clock := range []time.Time{now, now.Add(2 * time.Second), now.In(time.FixedZone("UTC+8", 8*3600))} {
		got, err := table.Decode(encoded, clock)
		if err != nil || !bytes.Equal(got, packet) {
			t.Fatal("midnight or timezone broke decoding", err)
		}
	}
	next := table.Encode(packet, now.Add(2*time.Second))
	if bytes.Equal(next[HeaderSize:], encoded[HeaderSize:]) {
		t.Fatal("daily mapping did not change")
	}
	for _, bad := range [][]byte{nil, encoded[:HeaderSize], table.Encode(packet, now.Add(-48*time.Hour)), table.Encode(packet, now.Add(48*time.Hour))} {
		if _, err := table.Decode(bad, now); err == nil {
			t.Fatal("short or stale frame accepted")
		}
	}
	bad := bytes.Clone(encoded)
	binary.BigEndian.PutUint64(bad[:HeaderSize], uint64(dayTimestamp(now)+1))
	if _, err := table.Decode(bad, now); err == nil {
		t.Fatal("non-midnight timestamp accepted")
	}
}

func TestConcurrentCreateAndMapping(t *testing.T) {
	path := filepath.Join(t.TempDir(), "table")
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			table, _, err := LoadOrCreate(path, 8)
			if err != nil {
				t.Error(err)
				return
			}
			for j := 0; j < 20; j++ {
				now := time.Now().Add(time.Duration(j%3-1) * 24 * time.Hour)
				data := []byte("concurrent mapping")
				decoded, err := table.Decode(table.Encode(data, now), now)
				if err != nil || !bytes.Equal(data, decoded) {
					t.Error("mapping race", err)
				}
			}
			loaded, err := Load(path)
			if err != nil || table.Credential() != loaded.Credential() {
				t.Error("concurrent create disagrees", err)
			}
		}()
	}
	workers.Wait()
}
