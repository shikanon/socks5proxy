//go:build linux && !android

package tcpopts

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

const supported = true

func configure(conn *net.TCPConn, algorithm string) (string, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return "", err
	}
	var selected string
	var socketErr error
	err = raw.Control(func(fd uintptr) {
		previous, e := unix.GetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION)
		if e != nil {
			socketErr = e
			return
		}
		if e = unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION, algorithm); e != nil {
			socketErr = e
			return
		}
		selected, e = unix.GetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION)
		if e != nil || selected != algorithm {
			// Keep compatibility even if the readback fails or does not match.
			restoreErr := unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION, previous)
			socketErr = fmt.Errorf("TCP congestion readback %q: %v; restore: %v", selected, e, restoreErr)
		}
	})
	if err != nil {
		return "", err
	}
	return selected, socketErr
}
