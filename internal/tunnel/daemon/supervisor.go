// Package daemon runs a separate supervisor process, leaving network ownership
// to one child and recovering its journal before any replacement starts.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/shikanon/socks5proxy/internal/tunnel/network"
)

type Options struct {
	Executable      string
	Args            []string
	StateDir        string
	RestartInterval time.Duration
	StopTimeout     time.Duration
	// Recover is injectable for process tests; production always recovers the journal.
	Recover func(context.Context) error
}

func ChildArgs(args []string) []string {
	out := make([]string, 0, len(args))
	for _, arg := range args {
		name := strings.TrimLeft(strings.SplitN(arg, "=", 2)[0], "-")
		if name != "daemon" {
			out = append(out, arg)
		}
	}
	return out
}

func Run(ctx context.Context, opts Options) error {
	if opts.RestartInterval <= 0 {
		opts.RestartInterval = 5 * time.Second
	}
	if opts.StopTimeout <= 0 {
		opts.StopTimeout = 20 * time.Second
	}
	if opts.Executable == "" {
		var err error
		opts.Executable, err = os.Executable()
		if err != nil {
			return err
		}
	}
	lock, err := network.AcquireLock(opts.StateDir, "daemon")
	if err != nil {
		return err
	}
	defer lock.Close()
	recoverNetwork := func() error {
		clientLock, err := network.AcquireLock(opts.StateDir, "client")
		if err != nil {
			return err
		}
		defer clientLock.Close()
		restoreCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = network.WriteStatus(opts.StateDir, "restoring", nil)
		if opts.Recover != nil {
			err = opts.Recover(restoreCtx)
		} else {
			err = network.RecoverClientState(restoreCtx, opts.StateDir, nil)
		}
		if err != nil {
			_ = network.WriteStatus(opts.StateDir, "error", err)
			return err
		}
		return network.WriteStatus(opts.StateDir, "direct", nil)
	}
	if err := recoverNetwork(); err != nil {
		return fmt.Errorf("supervisor startup recovery: %w", err)
	}
	for ctx.Err() == nil {
		cmd := exec.Command(opts.Executable, ChildArgs(opts.Args)...)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Start(); err != nil {
			return err
		}
		log.Printf("tunnel supervisor started child pid=%d", cmd.Process.Pid)
		exited := make(chan error, 1)
		go func() { exited <- cmd.Wait() }()
		var childErr error
		select {
		case childErr = <-exited:
		case <-ctx.Done():
			_ = stopChild(cmd.Process)
			timer := time.NewTimer(opts.StopTimeout)
			select {
			case childErr = <-exited:
			case <-timer.C:
				_ = cmd.Process.Kill()
				childErr = <-exited
			}
			timer.Stop()
		}
		log.Printf("tunnel supervisor child exited pid=%d error=%v", cmd.Process.Pid, childErr)
		if err := recoverNetwork(); err != nil {
			return errors.Join(childErr, fmt.Errorf("supervisor network recovery: %w", err))
		}
		if ctx.Err() != nil {
			return nil
		}
		timer := time.NewTimer(opts.RestartInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
	return nil
}
