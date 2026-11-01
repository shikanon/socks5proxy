package client

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/shikanon/socks5proxy/internal/tunnel"
	"github.com/shikanon/socks5proxy/internal/tunnel/protocol"
	"github.com/shikanon/socks5proxy/internal/tunnel/transport"
)

type connection struct {
	conn     transport.Conn
	response protocol.Message
	cipher   protocol.Cipher
	endpoint netip.Addr
}

func (c *connection) close() { _ = c.conn.CloseWithError(0, "watchdog reconnecting") }

type managedTunnel interface {
	parameters() protocol.Message
	relay(context.Context, *connection) error
	restore(context.Context) error
}

type watchdogHooks struct {
	connect  func(context.Context, bool) (*connection, error)
	activate func(context.Context, *connection) (managedTunnel, error)
	recover  func(context.Context) error
	status   func(string, error)
	now      func() time.Time
	wait     func(context.Context, time.Duration) error
}

func runWatchdog(ctx context.Context, c tunnel.ClientConfig, h watchdogHooks) (result error) {
	var active managedTunnel
	var deadline time.Time
	pendingRestore := false
	restore := func() error {
		h.status("restoring", nil)
		restoreCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		var err error
		if active != nil {
			err = active.restore(restoreCtx)
		} else {
			err = h.recover(restoreCtx)
		}
		if err != nil {
			h.status("error", err)
			return err
		}
		active, pendingRestore, deadline = nil, false, time.Time{}
		h.status("direct", nil)
		return nil
	}
	defer func() {
		if active != nil || pendingRestore {
			result = errors.Join(result, restore())
		}
	}()
	h.status("direct", nil)
	for ctx.Err() == nil {
		if pendingRestore || (active != nil && c.DisconnectPolicy == "direct" && !deadline.IsZero() && !h.now().Before(deadline)) {
			if err := restore(); err != nil {
				pendingRestore = true
				if h.wait(ctx, c.ReconnectInterval) != nil {
					break
				}
				continue
			}
		}
		attemptTimeout := 10 * time.Second
		if active != nil && c.DisconnectPolicy == "direct" && !deadline.IsZero() {
			attemptTimeout = min(attemptTimeout, deadline.Sub(h.now()))
		}
		attemptCtx, cancel := context.WithTimeout(ctx, attemptTimeout)
		conn, err := h.connect(attemptCtx, active != nil)
		cancel()
		if ctx.Err() != nil {
			if conn != nil {
				conn.close()
			}
			break
		}
		if err == nil && active != nil && c.DisconnectPolicy == "direct" && !deadline.IsZero() && !h.now().Before(deadline) {
			conn.close()
			continue
		}
		if err == nil && active != nil && !sameTunnelParameters(active.parameters(), conn.response) {
			conn.close()
			if c.DisconnectPolicy == "block" {
				return errors.New("server changed tunnel parameters; restart the client")
			}
			pendingRestore = true
			continue
		}
		if err == nil && active == nil {
			setupCtx, setupCancel := context.WithTimeout(ctx, 15*time.Second)
			active, err = h.activate(setupCtx, conn)
			setupCancel()
			if err != nil {
				pendingRestore = true
			}
		}
		if err == nil {
			deadline = time.Time{}
			h.status("tunnel", nil)
			err = active.relay(ctx, conn)
		}
		if conn != nil {
			conn.close()
		}
		if ctx.Err() != nil {
			break
		}
		if active == nil && c.DisconnectPolicy == "block" && !pendingRestore {
			return err
		}
		if active != nil {
			if deadline.IsZero() {
				deadline = h.now().Add(c.FallbackTimeout)
			}
			if errors.Is(err, errHealthTimeout) {
				deadline = h.now()
			}
			h.status("reconnecting", err)
		} else if pendingRestore {
			h.status("error", err)
		} else {
			h.status("direct", err)
		}
		delay := c.ReconnectInterval
		if active != nil {
			delay = time.Second
			if c.DisconnectPolicy == "direct" {
				delay = min(delay, max(0, deadline.Sub(h.now())))
			}
		}
		if h.wait(ctx, delay) != nil {
			break
		}
	}
	return nil
}
