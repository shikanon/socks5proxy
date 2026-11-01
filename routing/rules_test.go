package routing

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWebsiteRules(t *testing.T) {
	for _, tc := range []struct {
		pattern string
		matches []string
		misses  []string
	}{
		{"example.com", []string{"example.com", "EXAMPLE.COM."}, []string{"www.example.com", "example.com.evil", "notexample.com"}},
		{"*.example.com", []string{"example.com", "www.example.com", "a.b.example.com"}, []string{"notexample.com", "example.com.evil"}},
		{"api?.example.*", []string{"api1.example.com", "apia.example.co.uk"}, []string{"api.example.com", "api12.example.com"}},
		{"*", []string{"any.example", "127.0.0.1", "::1"}, nil},
		{"https://*.example.com:443/*", []string{"example.com", "a.example.com"}, []string{"other.test"}},
		{"bücher.example", []string{"bücher.example", "xn--bcher-kva.example"}, []string{"bucher.example"}},
		{"*.bücher.example", []string{"bücher.example", "shop.xn--bcher-kva.example"}, []string{"other.example"}},
		{"::ffff:127.0.0.1", []string{"127.0.0.1", "::ffff:127.0.0.1"}, []string{"127.0.0.2"}},
		{"https://[::1]/", []string{"::1", "0:0:0:0:0:0:0:1"}, []string{"::2"}},
		{"example.com:8443", []string{"example.com"}, []string{"other.test"}},
	} {
		t.Run(tc.pattern, func(t *testing.T) {
			rules, err := New([]string{tc.pattern})
			require.NoError(t, err)
			for _, host := range tc.matches {
				assert.True(t, rules.Match(host), host)
			}
			for _, host := range tc.misses {
				assert.False(t, rules.Match(host), host)
			}
		})
	}
	rules, err := New([]string{" EXAMPLE.COM. ", "https://example.com/", "", "example.com"})
	require.NoError(t, err)
	assert.Equal(t, []string{"example.com"}, rules.Patterns())
	copy := rules.Patterns()
	copy[0] = "*"
	assert.False(t, rules.Match("other.test"))
	assert.False(t, rules.Match(strings.Repeat("x", 254)))
	var empty *Rules
	assert.False(t, empty.Match("example.com"))
	assert.Empty(t, empty.Patterns())
}

func TestInvalidRules(t *testing.T) {
	for _, pattern := range []string{
		"https://example.com/private/*", "ftp://example.com", "https://u:p@example.com/",
		"https://example.com/?x=1", "https://example.com/#x", "example.com/path",
		"example.com:0", "example.com:65536", "example.com:bad",
		"https://example.com:0/", "https://", "a..example.com", ".", "[oops",
		strings.Repeat("a", 64) + ".com", "büch*.example",
	} {
		_, err := New([]string{pattern})
		assert.Error(t, err, pattern)
	}
	patterns := make([]string, MaxRules+1)
	for i := range patterns {
		patterns[i] = strings.Repeat("a", i/63+1) + "." + strings.Repeat("b", i%63+1)
	}
	_, err := New(patterns)
	require.ErrorContains(t, err, "exceed")
}

func TestLoadRules(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.txt")
	require.NoError(t, os.WriteFile(path, []byte("# comments\r\n\n*.example.com\r\n EXAMPLE.ORG \n"), 0600))
	rules, err := Load(path)
	require.NoError(t, err)
	assert.True(t, rules.Match("a.example.com"))
	assert.True(t, rules.Match("example.org"))
	assert.False(t, rules.Match("else.test"))
	require.NoError(t, os.WriteFile(path, []byte(strings.Repeat("#", MaxFileSize+1)), 0600))
	_, err = Load(path)
	require.ErrorContains(t, err, "1 MiB")
}
