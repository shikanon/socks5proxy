package client

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/shikanon/socks5proxy/internal/tunnel"
	"github.com/shikanon/socks5proxy/internal/tunnel/protocol"
)

type testTunnel struct {
	response  protocol.Message
	run       func(context.Context, *connection) error
	restoreFn func() error
	restores  int
}

func (t *testTunnel) parameters() protocol.Message                   { return t.response }
func (t *testTunnel) relay(ctx context.Context, c *connection) error { return t.run(ctx, c) }
func (t *testTunnel) restore(context.Context) error {
	t.restores++
	if t.restoreFn != nil {
		return t.restoreFn()
	}
	return nil
}
func testConnection(r protocol.Message) *connection {
	ctx, cancel := context.WithCancel(context.Background())
	return &connection{conn: &relayConn{ctx: ctx, cancel: cancel}, response: r}
}

func TestWatchdogFallbackAndReactivation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	config := tunnel.ClientConfig{}
	config.SetDefaults()
	now := time.Now()
	original := protocol.Message{ClientIPv4: "10.0.0.2", MTU: 1150}
	changed := protocol.Message{ClientIPv4: "10.0.0.3", MTU: 1150}
	first := &testTunnel{response: original, run: func(context.Context, *connection) error { return errors.New("disconnect") }}
	second := &testTunnel{response: changed, run: func(context.Context, *connection) error { cancel(); return context.Canceled }}
	connects, activations, failures := 0, 0, 0
	var modes []string
	h := watchdogHooks{
		now:     func() time.Time { return now },
		wait:    func(ctx context.Context, d time.Duration) error { now = now.Add(d); return ctx.Err() },
		status:  func(mode string, err error) { modes = append(modes, mode) },
		recover: func(context.Context) error { return nil },
		connect: func(ctx context.Context, retained bool) (*connection, error) {
			connects++
			if connects == 1 {
				return testConnection(original), nil
			}
			if retained {
				failures++
				if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 10*time.Second {
					t.Fatal("unbounded reconnect")
				}
				return nil, errors.New("unreachable")
			}
			if first.restores != 1 {
				t.Fatal("recaptured before restoration")
			}
			return testConnection(changed), nil
		},
		activate: func(_ context.Context, c *connection) (managedTunnel, error) {
			activations++
			if activations == 1 {
				return first, nil
			}
			return second, nil
		},
	}
	if err := runWatchdog(ctx, config, h); err != nil {
		t.Fatal(err)
	}
	if failures != 9 || activations != 2 || first.restores != 1 || second.restores != 1 {
		t.Fatalf("wrong lifecycle failures=%d activations=%d restores=%d/%d modes=%v", failures, activations, first.restores, second.restores, modes)
	}
}

func TestWatchdogDirectStartupAndRestoreRetries(t *testing.T) {
	for _, scenario := range []string{"initial_outage", "restore_failure", "fast_reconnect", "parameter_change", "block"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			config := tunnel.ClientConfig{}
			config.SetDefaults()
			if scenario == "block" {
				config.DisconnectPolicy = "block"
			}
			now := time.Now()
			r := protocol.Message{MTU: 1150}
			attempts, relays, activations := 0, 0, 0
			a := &testTunnel{response: r}
			a.run = func(context.Context, *connection) error {
				relays++
				if relays == 2 {
					cancel()
					return context.Canceled
				}
				if scenario == "restore_failure" {
					return errHealthTimeout
				}
				return errors.New("offline")
			}
			a.restoreFn = func() error {
				if scenario == "restore_failure" && a.restores == 1 {
					return errors.New("DNS failure")
				}
				return nil
			}
			var modes []string
			h := watchdogHooks{
				now: func() time.Time { return now }, wait: func(ctx context.Context, d time.Duration) error { now = now.Add(d); return ctx.Err() },
				status: func(mode string, _ error) { modes = append(modes, mode) }, recover: func(context.Context) error { return nil },
				connect: func(_ context.Context, retained bool) (*connection, error) {
					attempts++
					if scenario == "initial_outage" {
						if attempts == 3 {
							cancel()
						}
						return nil, errors.New("offline")
					}
					if scenario == "restore_failure" && attempts == 2 && a.restores < 2 {
						t.Fatal("connected before failed restore was retried")
					}
					resp := r
					if scenario == "parameter_change" && attempts == 2 {
						resp.MTU++
					}
					if scenario == "block" && attempts == 2 {
						cancel()
						return nil, errors.New("offline")
					}
					return testConnection(resp), nil
				},
				activate: func(_ context.Context, c *connection) (managedTunnel, error) {
					activations++
					a.response = c.response
					return a, nil
				},
			}
			if err := runWatchdog(ctx, config, h); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "initial_outage":
				if activations != 0 || a.restores != 0 {
					t.Fatal("startup outage changed network")
				}
			case "restore_failure":
				if a.restores != 3 || activations != 2 {
					t.Fatal("missing restoration retry")
				}
			case "fast_reconnect", "block":
				if activations != 1 || a.restores != 1 {
					t.Fatal("unnecessarily recreated TUN")
				}
			case "parameter_change":
				if activations != 2 || a.restores != 2 {
					t.Fatal("changed parameters did not recreate TUN")
				}
			}
		})
	}
}

func TestWatchdogHungReconnectCannotExtendDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := tunnel.ClientConfig{}
	c.SetDefaults()
	c.FallbackTimeout = 50 * time.Millisecond
	c.ReconnectInterval = time.Millisecond
	calls := 0
	a := &testTunnel{response: protocol.Message{}, run: func(context.Context, *connection) error { return errors.New("lost") }}
	var lost time.Time
	h := watchdogHooks{
		now: time.Now, wait: waitBackoff, status: func(mode string, _ error) {
			if mode == "reconnecting" && lost.IsZero() {
				lost = time.Now()
			}
		},
		recover:  func(context.Context) error { return nil },
		activate: func(context.Context, *connection) (managedTunnel, error) { return a, nil },
		connect: func(ctx context.Context, retained bool) (*connection, error) {
			calls++
			if calls == 1 {
				return testConnection(protocol.Message{}), nil
			}
			if retained {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			if a.restores != 1 || time.Since(lost) > 300*time.Millisecond {
				t.Fatal("hung authentication delayed restoration")
			}
			cancel()
			return nil, context.Canceled
		},
	}
	if err := runWatchdog(ctx, c, h); err != nil {
		t.Fatal(err)
	}
}
