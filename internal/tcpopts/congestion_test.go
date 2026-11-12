package tcpopts

import (
	"errors"
	"net"
	"testing"
)

func TestConfigureValidationAndOwnership(t *testing.T) {
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	if _, err := Configure(local, "not-an-algorithm"); err == nil {
		t.Fatal("invalid algorithm accepted")
	}
	if _, err := Configure(local, "bbr"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("non-TCP error = %v", err)
	}
	if got, err := Configure(local, "system"); err != nil || got != "system" {
		t.Fatalf("system mode = %q, %v", got, err)
	}
}
