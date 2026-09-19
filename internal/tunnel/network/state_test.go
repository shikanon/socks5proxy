package network

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type fakeRunner struct {
	commands []Command
	failAt   int
}

func (r *fakeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	r.commands = append(r.commands, Command{Name: name, Args: append([]string(nil), args...)})
	if r.failAt > 0 && len(r.commands) == r.failAt {
		return "", errors.New("command failed")
	}
	return "", nil
}

func TestTransactionRestoresAppliedCommandsInReverseOrder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	runner := &fakeRunner{}
	undo := []Command{
		{Name: "undo-1", Args: []string{"a"}},
		{Name: "undo-2", Args: []string{"b"}},
		{Name: "undo-3", Args: []string{"c"}},
	}
	tx, err := newTransaction(path, runner, undo)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.markApplied(3); err != nil {
		t.Fatal(err)
	}
	if err := tx.restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []Command{undo[2], undo[1], undo[0]}
	if !reflect.DeepEqual(runner.commands, want) {
		t.Fatalf("restore order mismatch: got %#v want %#v", runner.commands, want)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state file still exists: %v", err)
	}
}

func TestTransactionPersistsAppliedStepForCrashRecovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	runner := &fakeRunner{}
	tx, err := newTransaction(path, runner, []Command{{Name: "undo"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.markApplied(1); err != nil {
		t.Fatal(err)
	}

	reloaded, err := loadTransaction(path, runner)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.state.Applied != 1 {
		t.Fatalf("rollback intent was not persisted: %#v", reloaded.state)
	}
	if err := reloaded.restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) != 1 || runner.commands[0].Name != "undo" {
		t.Fatalf("unexpected recovery commands: %#v", runner.commands)
	}
}
