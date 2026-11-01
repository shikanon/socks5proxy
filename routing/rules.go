// Package routing matches website hostnames for selective proxy routing.
package routing

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

const (
	MaxRules    = 1024
	MaxFileSize = 1 << 20
)

// Rules is immutable and safe to share between proxy sessions and PAC handlers.
type Rules struct{ patterns []string }

// New accepts host globs or HTTP(S) URLs whose path is empty, "/" or "/*".
// "*.example.com" includes example.com and any depth of subdomains.
func New(patterns []string) (*Rules, error) {
	rules := &Rules{}
	seen := make(map[string]bool)
	for _, raw := range patterns {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		pattern, err := normalizePattern(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid website rule %q: %w", raw, err)
		}
		if !seen[pattern] {
			seen[pattern] = true
			rules.patterns = append(rules.patterns, pattern)
			if len(rules.patterns) > MaxRules {
				return nil, fmt.Errorf("website rules exceed %d entries", MaxRules)
			}
		}
	}
	return rules, nil
}

// Load reads one rule per line. Empty lines and lines starting with # are ignored.
func Load(path string) (*Rules, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, MaxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxFileSize {
		return nil, errors.New("website rules file exceeds 1 MiB")
	}
	var patterns []string
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			patterns = append(patterns, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return New(patterns)
}

func (r *Rules) Patterns() []string {
	if r == nil {
		return nil
	}
	return append([]string(nil), r.patterns...)
}

func (r *Rules) Match(host string) bool {
	if r == nil {
		return false
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if ip, err := netip.ParseAddr(host); err == nil {
		host = ip.Unmap().String()
	} else {
		var err error
		host, err = idna.Lookup.ToASCII(host)
		if err != nil || host == "" {
			return false
		}
	}
	if len(host) > 253 {
		return false
	}
	for _, pattern := range r.patterns {
		if globMatch(pattern, host) ||
			(strings.HasPrefix(pattern, "*.") && globMatch(pattern[2:], host)) {
			return true
		}
	}
	return false
}

func normalizePattern(raw string) (string, error) {
	host := strings.TrimSpace(raw)
	if strings.Contains(host, "://") {
		u, err := url.Parse(host)
		if err != nil {
			return "", err
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return "", errors.New("URL scheme must be http or https")
		}
		if u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
			(u.Path != "" && u.Path != "/" && u.Path != "/*") {
			return "", errors.New("rules match website hosts; URL paths, credentials, queries and fragments are unsupported")
		}
		if port := u.Port(); port != "" {
			number, err := strconv.Atoi(port)
			if err != nil || number < 1 || number > 65535 {
				return "", errors.New("invalid URL port")
			}
		}
		host = u.Hostname()
	} else if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Unmap().String(), nil
	} else if strings.Contains(host, ":") {
		var port string
		host, port, err = net.SplitHostPort(host)
		if err != nil {
			return "", errors.New("expected a hostname or an HTTP(S) URL")
		}
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return "", errors.New("invalid host port")
		}
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" {
		return "", errors.New("empty hostname")
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Unmap().String(), nil
	}
	labels := strings.Split(host, ".")
	for i, label := range labels {
		if label == "" {
			return "", errors.New("empty hostname label")
		}
		if !strings.ContainsAny(label, "*?") {
			ascii, err := idna.Lookup.ToASCII(label)
			if err != nil {
				return "", err
			}
			label = ascii
		}
		for _, char := range label {
			if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-' || char == '*' || char == '?') {
				return "", errors.New("wildcard labels must use ASCII letters, digits, hyphens, * or ?")
			}
		}
		if len(label) > 63 {
			return "", errors.New("hostname label exceeds 63 characters")
		}
		labels[i] = label
	}
	host = strings.Join(labels, ".")
	if len(host) > 253 {
		return "", errors.New("hostname exceeds 253 characters")
	}
	return host, nil
}

// globMatch uses a bounded iterative matcher, avoiding regex backtracking.
// '*' matches zero or more characters (including dots), '?' matches one.
func globMatch(pattern, host string) bool {
	p, h, star, retry := 0, 0, -1, 0
	for h < len(host) {
		switch {
		case p < len(pattern) && (pattern[p] == '?' || pattern[p] == host[h]):
			p++
			h++
		case p < len(pattern) && pattern[p] == '*':
			star, retry = p, h
			p++
		case star >= 0:
			p = star + 1
			retry++
			h = retry
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}
