package network

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

type Status struct {
	Mode      string    `json:"mode"`
	PID       int       `json:"pid"`
	Updated   time.Time `json:"updated"`
	LastError string    `json:"last_error,omitempty"`
}

func WriteStatus(stateDir, mode string, cause error) error {
	s := Status{Mode: mode, PID: os.Getpid(), Updated: time.Now().UTC()}
	if cause != nil {
		s.LastError = cause.Error()
	}
	dir := StateDir(stateDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".status-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := secureStateFile(f.Name()); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), filepath.Join(dir, "client-status.json"))
}

func ReadStatus(stateDir string) (Status, error) {
	var s Status
	data, err := os.ReadFile(filepath.Join(StateDir(stateDir), "client-status.json"))
	if err == nil {
		err = json.Unmarshal(data, &s)
	}
	return s, err
}

func ClientRunning(stateDir string) bool {
	lock, err := AcquireLock(stateDir, "client")
	if err != nil {
		return true
	}
	_ = lock.Close()
	return false
}
