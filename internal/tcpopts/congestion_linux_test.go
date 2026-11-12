//go:build linux && !android

package tcpopts

import (
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func current(t *testing.T, conn *net.TCPConn) string {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var got string
	var inner error
	if err = raw.Control(func(fd uintptr) { got, inner = unix.GetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION) }); err != nil {
		t.Fatal(err)
	}
	if inner != nil {
		t.Fatal(inner)
	}
	return got
}

func TestBBRDefaultAndFallback(t *testing.T) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	peer, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	conn, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	globalBefore, err := os.ReadFile("/proc/sys/net/ipv4/tcp_congestion_control")
	if err != nil {
		t.Fatal(err)
	}
	original := current(t, conn)
	t.Setenv("SOCKS5PROXY_TCP_CONGESTION", "system")
	ApplyDefault(conn)
	if got := current(t, conn); got != original {
		t.Fatalf("system changed %s to %s", original, got)
	}
	t.Setenv("SOCKS5PROXY_TCP_CONGESTION", "invalid")
	ApplyDefault(conn)
	if got := current(t, conn); got != original {
		t.Fatal("invalid selection changed existing socket")
	}

	t.Setenv("SOCKS5PROXY_TCP_CONGESTION", "")
	ApplyDefault(conn)
	available, err := os.ReadFile("/proc/sys/net/ipv4/tcp_available_congestion_control")
	if err != nil {
		t.Fatal(err)
	}
	bbrAvailable := false
	for _, name := range strings.Fields(string(available)) {
		if name == "bbr" {
			bbrAvailable = true
		}
	}
	if bbrAvailable && current(t, conn) != "bbr" {
		t.Fatal("available BBR was not selected by default")
	}
	if !bbrAvailable && current(t, conn) != original {
		t.Fatal("unavailable BBR changed original algorithm")
	}
	globalAfter, err := os.ReadFile("/proc/sys/net/ipv4/tcp_congestion_control")
	if err != nil || string(globalAfter) != string(globalBefore) {
		t.Fatal("global congestion configuration changed", err)
	}
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := peer.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ok" {
		t.Fatal("configuration interrupted TCP data", err)
	}
	if _, err := Configure(conn, "cubic"); err != nil {
		t.Fatal(err)
	}
	if current(t, conn) != "cubic" {
		t.Fatal("CUBIC override did not apply")
	}
	conn.Close()
	if _, err := Configure(conn, "bbr"); err == nil {
		t.Fatal("closed socket accepted")
	}
}
