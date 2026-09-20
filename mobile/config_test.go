package mobile

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/shikanon/socks5proxy/internal/tunnel/protocol"
)

func testConfig() config {
	return config{ServerAddr: "127.0.0.1:443", ClientID: "phone", Token: strings.Repeat("a", 32), Transport: "tcp-plain"}
}

func configJSON(t *testing.T, cfg config) string {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestParseConfig(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*config)
	}{
		{"no_host", func(c *config) { c.ServerAddr = ":443" }},
		{"no_port", func(c *config) { c.ServerAddr = "localhost" }},
		{"zero_port", func(c *config) { c.ServerAddr = "localhost:0" }},
		{"large_port", func(c *config) { c.ServerAddr = "localhost:65536" }},
		{"ipv6", func(c *config) { c.ServerAddr = "[::1]:443" }},
		{"no_id", func(c *config) { c.ClientID = " " }},
		{"short_token", func(c *config) { c.Token = "short" }},
		{"small_mtu", func(c *config) { c.MTU = 575 }},
		{"large_mtu", func(c *config) { c.MTU = 1401 }},
		{"dns", func(c *config) { c.DNS = "::1" }},
		{"transport", func(c *config) { c.Transport = "udp" }},
		{"obfs", func(c *config) { c.Obfs = "unknown" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig()
			tc.edit(&cfg)
			if _, err := parseConfig(configJSON(t, cfg)); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
	if _, err := parseConfig("{"); err == nil {
		t.Fatal("invalid JSON accepted")
	}
	for _, mtu := range []int{0, 576, 1400} {
		cfg := testConfig()
		cfg.Transport, cfg.Obfs, cfg.MTU = "", "", mtu
		got, err := parseConfig(configJSON(t, cfg))
		if err != nil || got.Transport != "quic" || got.Obfs != "none" || got.ServerName != "127.0.0.1" || got.MTU < 576 {
			t.Fatal("defaults or valid boundary failed", got, err)
		}
	}
}

func TestConfigTLS(t *testing.T) {
	cfg := testConfig()
	if got, err := cfg.tlsConfig(); err != nil || got != nil {
		t.Fatal("plaintext unexpectedly requires TLS")
	}
	cfg.Transport, cfg.CAPEM = "tcp", "invalid pem"
	if _, err := cfg.tlsConfig(); err == nil {
		t.Fatal("invalid CA accepted")
	}
	cfg.CAPEM = ""
	tls, err := cfg.tlsConfig()
	if err != nil || tls.InsecureSkipVerify || tls.MinVersion != tls.MaxVersion {
		t.Fatal("secure TLS defaults not applied", err)
	}
}

func TestConfigParameters(t *testing.T) {
	cfg := testConfig()
	cfg.MTU = 1150
	valid := protocol.Message{ClientIPv4: "10.0.0.2", ServerIPv4: "10.0.0.1", DNSIPv4: "1.1.1.1", MTU: 1150}
	for _, field := range []string{"client", "server", "dns", "mtu"} {
		t.Run(field, func(t *testing.T) {
			msg := valid
			switch field {
			case "client":
				msg.ClientIPv4 = "::1"
			case "server":
				msg.ServerIPv4 = "0.0.0.0"
			case "dns":
				msg.DNSIPv4 = "224.0.0.1"
			case "mtu":
				msg.MTU++
			}
			if _, err := cfg.parameters(msg, "127.0.0.1"); err == nil {
				t.Fatal("invalid negotiated parameter accepted")
			}
		})
	}
	cfg.DNS = "8.8.8.8"
	got, err := cfg.parameters(valid, "127.0.0.1")
	if err != nil || got.DNSIPv4 != cfg.DNS || got.EndpointIPv4 != "127.0.0.1" {
		t.Fatal("DNS override or endpoint lost", got, err)
	}
}
