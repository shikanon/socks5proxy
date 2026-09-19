package server

import (
	"net/netip"
	"testing"
)

func TestSessionTableReplacesClientAndKeepsCurrentRegistration(t *testing.T) {
	table := newSessionTable()
	first := &session{
		clientID: "desktop",
		addr:     netip.MustParseAddr("10.0.0.2"),
	}
	second := &session{
		clientID: "desktop",
		addr:     netip.MustParseAddr("10.0.0.3"),
	}
	if replaced := table.register(first); replaced != nil {
		t.Fatal("first registration unexpectedly replaced a session")
	}
	if replaced := table.register(second); replaced != first {
		t.Fatal("second registration did not replace the first session")
	}
	if got := table.byAddress(first.addr); got != nil {
		t.Fatal("old address still resolves to a session")
	}
	if got := table.byAddress(second.addr); got != second {
		t.Fatal("new address does not resolve to the current session")
	}

	table.remove(first)
	if got := table.byAddress(second.addr); got != second {
		t.Fatal("removing stale session removed the current session")
	}
	table.remove(second)
	if got := table.byAddress(second.addr); got != nil {
		t.Fatal("current session was not removed")
	}
}
