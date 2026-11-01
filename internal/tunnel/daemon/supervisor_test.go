package daemon

import (
	"context"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestSupervisorChild(t *testing.T) {
	if os.Getenv("S5P_DAEMON_HELPER") != "1" {
		return
	}
	if os.Getenv("S5P_DAEMON_HANG") == "1" {
		for {
			<-time.After(time.Hour)
		}
	}
	os.Exit(23)
}

func TestSupervisorCrashRecoveryAndCancellation(t *testing.T) {
	t.Setenv("S5P_DAEMON_HELPER", "1")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	err := Run(ctx, Options{Executable: os.Args[0], Args: []string{"-test.run=^TestSupervisorChild$"}, StateDir: t.TempDir(), RestartInterval: time.Millisecond, Recover: func(context.Context) error {
		calls++
		if calls == 3 {
			cancel()
		}
		return nil
	}})
	if err != nil || calls != 3 {
		t.Fatalf("crash recovery failed: %v calls=%d", err, calls)
	}
}

func TestSupervisorStopsWhenRecoveryFails(t *testing.T) {
	t.Setenv("S5P_DAEMON_HELPER", "1")
	calls := 0
	expected := errors.New("restore failed")
	err := Run(context.Background(), Options{Executable: os.Args[0], Args: []string{"-test.run=^TestSupervisorChild$"}, StateDir: t.TempDir(), Recover: func(context.Context) error {
		calls++
		if calls == 2 {
			return expected
		}
		return nil
	}})
	if !errors.Is(err, expected) || calls != 2 {
		t.Fatal("supervisor ignored recovery failure", err, calls)
	}
}

func TestChildArgs(t *testing.T) {
	got := ChildArgs([]string{"-mode", "tunnel", "-daemon", "-config", "a b.json", "--daemon=true", "-daemon=false"})
	if !reflect.DeepEqual(got, []string{"-mode", "tunnel", "-config", "a b.json"}) {
		t.Fatal(got)
	}
}

func TestSupervisorGracefulStopAndInterruptedBackoff(t *testing.T) {
	for _, hang := range []bool{false, true} {
		t.Run(map[bool]string{false: "interrupt_backoff", true: "stop_child"}[hang], func(t *testing.T) {
			t.Setenv("S5P_DAEMON_HELPER", "1")
			if hang {
				t.Setenv("S5P_DAEMON_HANG", "1")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
			defer cancel()
			calls := 0
			start := time.Now()
			err := Run(ctx, Options{Executable: os.Args[0], Args: []string{"-test.run=^TestSupervisorChild$"}, StateDir: t.TempDir(), RestartInterval: time.Second, StopTimeout: time.Second, Recover: func(context.Context) error { calls++; return nil }})
			if err != nil || calls != 2 || time.Since(start) > 800*time.Millisecond {
				t.Fatalf("stop delayed: %v recovery=%d", err, calls)
			}
		})
	}
}
