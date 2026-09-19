package client

import (
	"context"
	"testing"

	"github.com/shikanon/socks5proxy/internal/tunnel/protocol"
)

func TestSameTunnelParameters(t *testing.T) {
	base := protocol.Message{
		ClientIPv4: "10.255.0.2",
		ServerIPv4: "10.255.0.1",
		DNSIPv4:    "1.1.1.1",
		MTU:        1280,
		Obfs:       "random",
	}
	if !sameTunnelParameters(base, base) {
		t.Fatal("identical parameters were rejected")
	}
	changed := base
	changed.ClientIPv4 = "10.255.0.3"
	if sameTunnelParameters(base, changed) {
		t.Fatal("changed client address was accepted")
	}
}

func TestResolveServerRejectsIPv6Endpoint(t *testing.T) {
	if _, _, err := resolveServer(context.Background(), "[2001:db8::1]:443", "vpn.example.com"); err == nil {
		t.Fatal("expected IPv6 endpoint error")
	}
}
