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

func TestRestoreFailureRemainsPendingAfterLowerStepsSucceed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	r := &fakeRunner{failAt: 2}
	tx, err := newTransaction(path, r, []Command{{Name: "first"}, {Name: "middle"}, {Name: "last"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.markApplied(3); err != nil {
		t.Fatal(err)
	}
	if tx.restore(context.Background()) == nil {
		t.Fatal("expected failure")
	}
	retry := &fakeRunner{}
	reloaded, err := loadTransaction(path, retry)
	if err != nil {
		t.Fatal(err)
	}
	if err := reloaded.restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(retry.commands) != 1 || retry.commands[0].Name != "middle" {
		t.Fatalf("lost failed undo: %+v", retry.commands)
	}
}

func TestAbsentResourcesAndExclusiveLocks(t *testing.T) {
	for _, c := range []Command{
		{Name: "ip", Args: []string{"route", "del", "0.0.0.0/1"}},
		{Name: "ip", Args: []string{"link", "set", "dev", "gone", "down"}},
	} {
		if !alreadyAbsent(c, "Cannot find device gone: does not exist") {
			t.Fatal("missing resource not recoverable")
		}
		if alreadyAbsent(c, "does not exist: Operation not permitted") {
			t.Fatal("ignored permission failure")
		}
	}
	if alreadyAbsent(Command{Name: "resolvectl", Args: []string{"revert", "gone"}}, "does not exist") {
		t.Fatal("ignored DNS failure")
	}
	dir := t.TempDir()
	a, err := AcquireLock(dir, "client")
	if err != nil {
		t.Fatal(err)
	}
	if b, err := AcquireLock(dir, "client"); err == nil {
		b.Close()
		t.Fatal("duplicate client lock")
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := AcquireLock(dir, "client")
	if err != nil {
		t.Fatal(err)
	}
	b.Close()
}
