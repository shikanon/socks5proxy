// Package tcpopts selects BBR on program-owned Linux TCP connections without
// changing machine-wide kernel settings. Unsupported kernels retain their default.
package tcpopts

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
)

var ErrUnsupported = errors.New("TCP congestion selection is unsupported")
var reportFailure sync.Once
var reportSelected sync.Once

// Configure sets a single connection's algorithm. "system" leaves it unchanged.
// It never owns or closes conn. Non-TCP connections and unsupported platforms are
// reported as ErrUnsupported, so callers can preserve their existing transport.
func Configure(conn net.Conn, algorithm string) (string, error) {
	if algorithm == "system" {
		return "system", nil
	}
	if algorithm != "bbr" && algorithm != "cubic" {
		return "", fmt.Errorf("invalid TCP congestion algorithm %q", algorithm)
	}
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return "", ErrUnsupported
	}
	return configure(tcp, algorithm)
}

// ApplyDefault attempts BBR before forwarding data. The environment override is
// process-local: SOCKS5PROXY_TCP_CONGESTION=bbr|cubic|system. Failure is non-fatal.
func ApplyDefault(conn net.Conn) {
	if !supported {
		return
	}
	algorithm := os.Getenv("SOCKS5PROXY_TCP_CONGESTION")
	if algorithm == "" {
		algorithm = "bbr"
	}
	selected, err := Configure(conn, algorithm)
	if err != nil {
		reportFailure.Do(func() {
			log.Printf("TCP congestion %s unavailable; retaining existing socket algorithm: %v", algorithm, err)
		})
		return
	}
	if selected != "system" {
		reportSelected.Do(func() { log.Printf("TCP congestion selected: %s (per socket; global settings unchanged)", selected) })
	}
}
