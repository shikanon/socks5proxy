//go:build windows

package network

import (
	"fmt"
	"os/exec"
)

func secureStateFile(path string) error {
	output, err := exec.Command(
		"icacls.exe",
		path,
		"/inheritance:r",
		"/grant:r",
		"*S-1-5-18:F",
		"*S-1-5-32-544:F",
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("secure network state ACL: %w: %s", err, output)
	}
	return nil
}
