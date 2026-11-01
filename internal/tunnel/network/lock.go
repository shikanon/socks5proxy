package network

import (
	"fmt"
	"os"
	"path/filepath"
)

type Lock struct{ file *os.File }

// AcquireLock holds an OS lock until Close or process death. Files remain so
// removing/recreating a path cannot create a second independently locked inode.
func AcquireLock(stateDir, name string) (*Lock, error) {
	dir := StateDir(stateDir)
	if name != "client" && name != "daemon" {
		return nil, fmt.Errorf("invalid lock name")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, name+".lock")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := secureStateFile(path); err != nil {
		f.Close()
		return nil, err
	}
	if err := lockFile(f); err != nil {
		f.Close()
		return nil, fmt.Errorf("%s already running or state directory locked: %w", name, err)
	}
	return &Lock{file: f}, nil
}

func (l *Lock) Close() error { return l.file.Close() }
