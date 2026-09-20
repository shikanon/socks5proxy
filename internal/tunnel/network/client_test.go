package network

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"testing"
)

type responseRunner struct {
	responses []string
	calls     []Command
	failOn    string
}

func (r *responseRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	r.calls = append(r.calls, Command{Name: name, Args: append([]string(nil), args...)})
	if name+" "+strings.Join(args, " ") == r.failOn {
		return "", errors.New("injected command failure")
	}
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

func TestLinuxDNSLifecycle(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Apply uses host platform")
	}
	for _, failOn := range []string{"", "resolvectl domain utun9 ~.", "resolvectl flush-caches"} {
		t.Run("failure="+failOn, func(t *testing.T) {
			runner := &responseRunner{
				responses: []string{"default via 192.168.1.1 dev eth0\n", "", "nameserver 127.0.0.53\n"},
				failOn:    failOn,
			}
			manager, err := NewClientManager(clientTestOptions(t.TempDir()), runner)
			if err != nil {
				t.Fatal(err)
			}
			err = manager.Apply(context.Background())
			if failOn == "" {
				if err != nil {
					t.Fatal(err)
				}
				if err := manager.Restore(context.Background()); err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("expected DNS failure")
			}
			dnsApplied, domainApplied, dnsRestored := false, false, false
			for _, call := range runner.calls {
				command := call.Name + " " + strings.Join(call.Args, " ")
				switch command {
				case "resolvectl dns utun9 1.1.1.1":
					dnsApplied = true
				case "resolvectl domain utun9 ~.":
					domainApplied = true
				case "ip route del 128.0.0.0/1":
					if !dnsRestored {
						t.Fatal("routes restored before DNS")
					}
				}
				if call.Name == "sh" && call.Args[len(call.Args)-1] == "utun9" &&
					strings.Contains(command, `resolvectl revert "$1"`) &&
					strings.Contains(command, "resolvectl flush-caches") {
					dnsRestored = true
				}
			}
			if !dnsApplied || !domainApplied || !dnsRestored {
				t.Fatalf("incomplete DNS lifecycle: %+v", runner.calls)
			}
			if _, err := os.Stat(manager.path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("state left after restore: %v", err)
			}
		})
	}
}

func TestLinuxDNSPreflightAndOptOut(t *testing.T) {
	for _, test := range []struct {
		name string
		skip bool
		conf string
		fail string
	}{
		{name: "missing resolved", fail: "resolvectl status"},
		{name: "direct resolver", conf: "nameserver 106.12.199.25\n"},
		{name: "empty resolv.conf"},
		{name: "mixed resolvers", conf: "nameserver 127.0.0.53\nnameserver 8.8.8.8\n"},
		{name: "namespace opt-out", skip: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := &responseRunner{
				responses: []string{"default via 192.168.1.1 dev eth0\n", "", test.conf},
				failOn:    test.fail,
			}
			options := clientTestOptions(t.TempDir())
			options.SkipLinuxDNS = test.skip
			manager, err := NewClientManager(options, runner)
			if err != nil {
				t.Fatal(err)
			}
			forward, _, err := manager.planLinux(context.Background())
			if !test.skip {
				if err == nil || len(forward) != 0 {
					t.Fatal("DNS preflight must fail before network changes")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, command := range append(runner.calls, forward...) {
				if command.Name == "resolvectl" {
					t.Fatal("namespace opt-out must not contact host resolved")
				}
			}
		})
	}
}
