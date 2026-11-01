package network

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const stateVersion = 1

type transactionState struct {
	Version  int       `json:"version"`
	Applied  int       `json:"applied"`
	Undo     []Command `json:"undo"`
	Restored []bool    `json:"restored,omitempty"`
}

type transaction struct {
	path   string
	runner Runner
	state  transactionState
}

func newTransaction(path string, runner Runner, undo []Command) (*transaction, error) {
	tx := &transaction{
		path:   path,
		runner: runner,
		state: transactionState{
			Version: stateVersion,
			Undo:    undo,
		},
	}
	if err := tx.save(); err != nil {
		return nil, err
	}
	return tx, nil
}

func loadTransaction(path string, runner Runner) (*transaction, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var state transactionState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("decode network state: %w", err)
	}
	if state.Version != stateVersion || state.Applied < 0 || state.Applied > len(state.Undo) ||
		(len(state.Restored) != 0 && len(state.Restored) != len(state.Undo)) {
		return nil, errors.New("unsupported or invalid network state")
	}
	return &transaction{path: path, runner: runner, state: state}, nil
}

func (t *transaction) markApplied(count int) error {
	t.state.Applied = count
	return t.save()
}

func (t *transaction) save() error {
	if err := os.MkdirAll(filepath.Dir(t.path), 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	payload, err := json.MarshalIndent(t.state, "", "  ")
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(t.path), ".network-state-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return err
	}
	if err := secureStateFile(tempName); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(payload); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempName, t.path); err != nil {
		return err
	}
	return secureStateFile(t.path)
}

func (t *transaction) restore(ctx context.Context) error {
	if len(t.state.Restored) == 0 {
		t.state.Restored = make([]bool, len(t.state.Undo))
	}
	var joined error
	for i := t.state.Applied - 1; i >= 0; i-- {
		if t.state.Restored[i] {
			continue
		}
		command := t.state.Undo[i]
		output, err := t.runner.Run(ctx, command.Name, command.Args...)
		if err != nil && !alreadyAbsent(command, output+" "+err.Error()) {
			joined = errors.Join(joined, err)
			continue
		}
		t.state.Restored[i] = true
		if err := t.save(); err != nil {
			t.state.Restored[i] = false
			joined = errors.Join(joined, err)
		}
	}
	if joined != nil {
		return joined
	}
	return os.Remove(t.path)
}

// Crash recovery may run after the kernel has already removed a dead TUN.
// Never swallow permission, DNS, or sysctl failures.
func alreadyAbsent(c Command, output string) bool {
	s := strings.ToLower(output)
	if strings.Contains(s, "permission") || strings.Contains(s, "not permitted") || strings.Contains(s, "access is denied") {
		return false
	}
	args := strings.Join(c.Args, " ")
	switch c.Name {
	case "ip":
		if strings.Contains(args, " del ") || strings.Contains(args, "link set") {
			return strings.Contains(s, "cannot find device") || strings.Contains(s, "does not exist") ||
				strings.Contains(s, "no such process") || strings.Contains(s, "cannot assign requested address")
		}
	case "route":
		return strings.Contains(args, "delete") && strings.Contains(s, "not in table")
	case "ifconfig":
		return (strings.Contains(args, "down") || strings.Contains(args, "-alias")) &&
			(strings.Contains(s, "does not exist") || strings.Contains(s, "no such interface") || strings.Contains(s, "can't assign requested address"))
	case "iptables", "ip6tables":
		return strings.Contains(args, "-D ") && (strings.Contains(s, "bad rule") || strings.Contains(s, "no chain/target/match"))
	}
	return false
}
