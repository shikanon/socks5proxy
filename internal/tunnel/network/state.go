package network

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const stateVersion = 1

type transactionState struct {
	Version int       `json:"version"`
	Applied int       `json:"applied"`
	Undo    []Command `json:"undo"`
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
	if state.Version != stateVersion || state.Applied < 0 || state.Applied > len(state.Undo) {
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
	var joined error
	for i := t.state.Applied - 1; i >= 0; i-- {
		command := t.state.Undo[i]
		if _, err := t.runner.Run(ctx, command.Name, command.Args...); err != nil {
			joined = errors.Join(joined, err)
			continue
		}
		t.state.Applied = i
		if err := t.save(); err != nil {
			joined = errors.Join(joined, err)
		}
	}
	if joined != nil {
		return joined
	}
	return os.Remove(t.path)
}
