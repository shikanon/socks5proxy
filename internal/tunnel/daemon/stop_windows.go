//go:build windows

package daemon

import "os"

// Windows console children do not support os.Process.Signal. The parent
// restores the durable journal after termination.
func stopChild(p *os.Process) error { return p.Kill() }
