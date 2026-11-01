//go:build !windows

package daemon

import (
	"os"
	"syscall"
)

func stopChild(p *os.Process) error { return p.Signal(syscall.SIGTERM) }
