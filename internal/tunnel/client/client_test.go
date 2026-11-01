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

func TestResolveServerIPv6Endpoint(t *testing.T) {
	addr, name, err := resolveServer(context.Background(), "[2001:db8::1]:443", "vpn.example.com")
	if err != nil || addr.String() != "2001:db8::1" || name != "vpn.example.com" {
		t.Fatal("IPv6 endpoint resolution failed", addr, name, err)
	}
	for _, endpoint := range []string{"[::]:443", "[ff00::1]:443", "[fe80::1%en0]:443"} {
		if _, _, err := resolveServer(context.Background(), endpoint, ""); err == nil {
			t.Fatal("invalid endpoint accepted", endpoint)
		}
	}
}

func TestIPv6ReconnectParameters(t *testing.T) {
	base := protocol.Message{IPv6: true, ClientIPv6: "fd00::2", ServerIPv6: "fd00::1", DNSIPv6: "2001:db8::53", MTU: 1280}
	for _, edit := range []func(*protocol.Message){
		func(m *protocol.Message) { m.IPv6 = false },
		func(m *protocol.Message) { m.ClientIPv6 = "fd00::3" },
		func(m *protocol.Message) { m.ServerIPv6 = "fd00::4" },
		func(m *protocol.Message) { m.DNSIPv6 = "" },
	} {
		m := base
		edit(&m)
		if sameTunnelParameters(base, m) {
			t.Fatal("changed IPv6 parameters accepted on reconnect")
		}
	}
}
