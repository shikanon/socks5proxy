//go:build !windows

package network

import "os"

func secureStateFile(path string) error {
	return os.Chmod(path, 0o600)
}
