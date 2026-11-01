package server

import (
	"net/netip"
	"sync"
	"testing"
)

func TestIPv6ReservationsReuseIPv4Offsets(t *testing.T) {
	a, _ := NewAddressPool("10.40.0.0/24")
	b, _ := NewAddressPool("10.40.0.0/24")
	_ = a.Reserve([]string{"a", "b", "c"})
	_ = b.Reserve([]string{"c", "a", "b"})
	prefix := netip.MustParsePrefix("fd00:5:5::/64")
	if got := a.IPv6(prefix, a.Server()).String(); got != "fd00:5:5::1" {
		t.Fatal("incorrect IPv6 server lease", got)
	}
	seen := make(map[netip.Addr]bool)
	for _, id := range []string{"a", "b", "c"} {
		x, _ := a.Acquire(id)
		y, _ := b.Acquire(id)
		x6, y6 := a.IPv6(prefix, x), b.IPv6(prefix, y)
		if x6 != y6 || !prefix.Contains(x6) || seen[x6] {
			t.Fatal("unstable or duplicate IPv6 lease", x6, y6)
		}
		seen[x6] = true
	}
}

func TestAddressPoolAllocatesUniqueAddressesAndReusesClientAddress(t *testing.T) {
	pool, err := NewAddressPool("10.20.30.0/29")
	if err != nil {
		t.Fatal(err)
	}
	if got := pool.Server().String(); got != "10.20.30.1" {
		t.Fatalf("unexpected server address %s", got)
	}

	first, err := pool.Acquire("a")
	if err != nil {
		t.Fatal(err)
	}
	if first.String() != "10.20.30.2" {
		t.Fatalf("unexpected first client address: %s", first)
	}

	const clients = 4
	var wg sync.WaitGroup
	results := make(chan string, clients)
	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			addr, acquireErr := pool.Acquire(string(rune('b' + index)))
			if acquireErr != nil {
				t.Errorf("acquire: %v", acquireErr)
				return
			}
			results <- addr.String()
		}(i)
	}
	wg.Wait()
	close(results)

	seen := make(map[string]bool)
	for addr := range results {
		if seen[addr] {
			t.Fatalf("duplicate address %s", addr)
		}
		seen[addr] = true
	}
	reused, err := pool.Acquire("a")
	if err != nil {
		t.Fatal(err)
	}
	if reused != first {
		t.Fatalf("client address changed: got %s want %s", reused, first)
	}
}

func TestAddressPoolExhaustion(t *testing.T) {
	pool, err := NewAddressPool("10.0.0.0/30")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Acquire("only-client"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Acquire("extra-client"); err == nil {
		t.Fatal("expected address pool exhaustion")
	}
}

func TestAddressPoolReservationsAreStableAcrossRestart(t *testing.T) {
	clients := []string{"workstation-b", "workstation-a", "workstation-c"}
	first, err := NewAddressPool("10.40.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewAddressPool("10.40.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Reserve(clients); err != nil {
		t.Fatal(err)
	}
	if err := second.Reserve([]string{"workstation-c", "workstation-b", "workstation-a"}); err != nil {
		t.Fatal(err)
	}
	for _, clientID := range clients {
		firstAddr, _ := first.Acquire(clientID)
		secondAddr, _ := second.Acquire(clientID)
		if firstAddr != secondAddr {
			t.Fatalf("unstable reservation for %s: %s != %s", clientID, firstAddr, secondAddr)
		}
	}
}
