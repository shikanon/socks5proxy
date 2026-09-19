package network

import (
	"context"
	"net/netip"
	"strings"
	"testing"
)

type responseRunner struct {
	responses []string
	calls     []Command
}

func (r *responseRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	r.calls = append(r.calls, Command{Name: name, Args: append([]string(nil), args...)})
	if len(r.responses) == 0 {
		return "", nil
	}
	response := r.responses[0]
	r.responses = r.responses[1:]
	return response, nil
}

func clientTestOptions(stateDir string) ClientOptions {
	return ClientOptions{
		TUNName:    "utun9",
		ClientIP:   netip.MustParseAddr("10.255.0.2"),
		ServerIP:   netip.MustParseAddr("203.0.113.10"),
		TunnelPeer: netip.MustParseAddr("10.255.0.1"),
		DNS:        netip.MustParseAddr("1.1.1.1"),
		MTU:        1280,
		StateDir:   stateDir,
	}
}

func TestDarwinPlanPreservesNetworkServiceDNS(t *testing.T) {
	runner := &responseRunner{responses: []string{
		"route to: default\ngateway: 192.168.1.1\ninterface: en0\n",
		"(1) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n",
		"192.168.1.1\n9.9.9.9\n",
	}}
	manager, err := NewClientManager(clientTestOptions(t.TempDir()), runner)
	if err != nil {
		t.Fatal(err)
	}
	forward, undo, err := manager.planDarwin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(forward[1].Args, " "); !strings.Contains(got, "203.0.113.10 192.168.1.1") {
		t.Fatalf("server bypass route is incorrect: %s", got)
	}
	dnsUndo := strings.Join(undo[4].Args, " ")
	if dnsUndo != "-setdnsservers Wi-Fi 192.168.1.1 9.9.9.9" {
		t.Fatalf("DNS restore is incorrect: %s", dnsUndo)
	}
}

func TestWindowsPlanPreservesPhysicalDNS(t *testing.T) {
	runner := &responseRunner{responses: []string{
		`{"InterfaceIndex":7,"NextHop":"192.168.1.1","DNS":["192.168.1.1","9.9.9.9"]}`,
	}}
	manager, err := NewClientManager(clientTestOptions(t.TempDir()), runner)
	if err != nil {
		t.Fatal(err)
	}
	forward, undo, err := manager.planWindows(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(forward[5].Args, " "); !strings.Contains(got, "InterfaceIndex 7") || !strings.Contains(got, "'1.1.1.1'") {
		t.Fatalf("physical DNS update is incorrect: %s", got)
	}
	if got := strings.Join(undo[5].Args, " "); !strings.Contains(got, "@('192.168.1.1','9.9.9.9')") {
		t.Fatalf("physical DNS restore is incorrect: %s", got)
	}
}

func TestClientManagerRejectsUnsafeInterfaceName(t *testing.T) {
	options := clientTestOptions(t.TempDir())
	options.TUNName = "utun0; rm -rf /"
	if _, err := NewClientManager(options, &responseRunner{}); err == nil {
		t.Fatal("expected unsafe interface name error")
	}
}
