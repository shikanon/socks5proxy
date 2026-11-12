//go:build !linux || android

package tcpopts

import "net"

const supported = false

func configure(_ *net.TCPConn, _ string) (string, error) {
	return "", ErrUnsupported
}
