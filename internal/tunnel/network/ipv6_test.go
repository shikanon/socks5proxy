package network

import (
	"context"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestDualStackClientPlans(t *testing.T) {
	for _, platform := range []string{"darwin", "linux", "windows"} {
		for _, endpoint6 := range []bool{false, true} {
			t.Run(platform+map[bool]string{false: "/endpoint4", true: "/endpoint6"}[endpoint6], func(t *testing.T) {
				o := clientTestOptions(t.TempDir())
				o.ClientIPv6, o.TunnelPeerIPv6 = netip.MustParseAddr("fd00::2"), netip.MustParseAddr("fd00::1")
				o.DNSIPv6 = netip.MustParseAddr("2001:db8::53")
				gateway := "192.168.1.1"
				hostSuffix := "/32"
				if endpoint6 {
					o.ServerIP, gateway, hostSuffix = netip.MustParseAddr("2001:db8::10"), "fe80::1", "/128"
				}
				r := &responseRunner{}
				m, err := NewClientManager(o, r)
				if err != nil {
					t.Fatal(err)
				}
				var f, u []Command
				switch platform {
				case "darwin":
					r.responses = []string{"gateway: " + gateway + "\ninterface: en0", "(1) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)", "9.9.9.9"}
					f, u, err = m.planDarwin(context.Background())
				case "linux":
					r.responses = []string{"default via " + gateway + " dev eth0", "", "nameserver 127.0.0.53"}
					f, u, err = m.planLinux(context.Background())
				case "windows":
					r.responses = []string{`{"InterfaceIndex":7,"NextHop":"` + gateway + `","DNS":["9.9.9.9","2001:db8::54"]}`, `{"IPv4":1500,"IPv6":1500}`}
					f, u, err = m.planWindows(context.Background())
				}
				if err != nil || len(f) != len(u) {
					t.Fatal("unpaired network plan", len(f), len(u), err)
				}
				wire := ""
				for _, c := range f {
					wire += c.Name + " " + strings.Join(c.Args, " ") + "\n"
				}
				for _, want := range []string{"fd00::2", "::/1", "8000::/1", "2001:db8::53", o.ServerIP.String()} {
					if !strings.Contains(wire, want) {
						t.Fatal("missing dual-stack network command", want, wire)
					}
				}
				if strings.Contains(wire, "-reject") || strings.Contains(wire, "FirewallRule") {
					t.Fatal("dual-stack still blocks IPv6")
				}
				if platform != "darwin" && !strings.Contains(wire, o.ServerIP.String()+hostSuffix) {
					t.Fatal("endpoint bypass has wrong prefix")
				}
				// Exercise rollback of every possible applied prefix on this host.
				for applied := 1; applied <= len(f); applied++ {
					runner := &fakeRunner{}
					path := t.TempDir() + "/state.json"
					tx, err := newTransaction(path, runner, u)
					if err != nil {
						t.Fatal(err)
					}
					if err := tx.markApplied(applied); err != nil {
						t.Fatal(err)
					}
					if err := tx.restore(context.Background()); err != nil {
						t.Fatal(err)
					}
					for i := 0; i < applied; i++ {
						if !reflect.DeepEqual(runner.commands[i], u[applied-i-1]) {
							t.Fatal("incorrect IPv6 rollback order")
						}
					}
				}
			})
		}
	}
	o := clientTestOptions(t.TempDir())
	o.DNSIPv6 = netip.MustParseAddr("2001:db8::53")
	if _, err := NewClientManager(o, &responseRunner{}); err == nil {
		t.Fatal("partial IPv6 network parameters accepted")
	}
}

func TestDualStackServerPlanAndFailureRestore(t *testing.T) {
	o := ServerOptions{TUNName: "s5ptest", TunnelPrefix: netip.MustParsePrefix("10.0.0.0/24"), ServerIP: netip.MustParseAddr("10.0.0.1"),
		TunnelPrefix6: netip.MustParsePrefix("fd00::/64"), ServerIPv6: netip.MustParseAddr("fd00::1"),
		MTU: 1280, ManageNetwork: true, OutboundInterface: "eth0"}
	r := &responseRunner{responses: []string{"0", "1", "0"}}
	m := &ServerManager{options: o, runner: r}
	f, u, err := m.plan(context.Background())
	if err != nil || len(f) != len(u) {
		t.Fatal("unpaired server plan", err)
	}
	var joined string
	for _, c := range f {
		joined += c.Name + " " + strings.Join(c.Args, " ") + "\n"
	}
	for _, want := range []string{"fd00::1/64", "accept_ra=2", "all.forwarding=1", "ip6tables -A FORWARD", "ip6tables -t nat -A POSTROUTING -s fd00::/64 -o eth0"} {
		if !strings.Contains(joined, want) {
			t.Fatal("missing IPv6 server configuration", want)
		}
	}
	if strings.Index(joined, "accept_ra=2") > strings.Index(joined, "all.forwarding=1") {
		t.Fatal("forwarding enabled before preserving RA")
	}
	for failure := range f {
		r := &responseRunner{responses: []string{"0", "1", "0"}, failOn: f[failure].Name + " " + strings.Join(f[failure].Args, " ")}
		m := &ServerManager{options: o, runner: r, path: t.TempDir() + "/state.json"}
		if err := m.Apply(context.Background()); err == nil {
			t.Fatal("injected network failure ignored")
		}
		if _, err := os.Stat(m.path); !os.IsNotExist(err) {
			t.Fatal("rollback left network state", err)
		}
		restored := r.calls[3+failure+1:]
		for i, c := range restored {
			if !reflect.DeepEqual(c, u[failure-i-1]) {
				t.Fatal("server failure did not restore applied commands", failure, c)
			}
		}
		if len(restored) != failure {
			t.Fatal("incorrect rollback command count")
		}
	}
	o.ManageNetwork = false
	m.options = o
	f, u, err = m.plan(context.Background())
	if err != nil || len(f) != 3 || len(u) != 3 {
		t.Fatal("externally managed network must configure TUN addresses only")
	}
}
