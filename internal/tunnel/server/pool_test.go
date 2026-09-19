package server

import (
	"sync"
	"testing"
)

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
