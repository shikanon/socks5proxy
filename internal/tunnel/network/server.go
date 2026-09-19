package network

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

type ServerOptions struct {
	TUNName           string
	TunnelPrefix      netip.Prefix
	ServerIP          netip.Addr
	MTU               int
	OutboundInterface string
	ManageNetwork     bool
	StateDir          string
}

type ServerManager struct {
	options ServerOptions
	runner  Runner
	path    string
}

func NewServerManager(options ServerOptions, runner Runner) (*ServerManager, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("tunnel server networking is only supported on Linux, got %s", runtime.GOOS)
	}
	if runner == nil {
		runner = ExecRunner{}
	}
	if !safeInterfaceName(options.TUNName) {
		return nil, errors.New("invalid TUN interface name")
	}
	if options.ManageNetwork && !safeInterfaceName(options.OutboundInterface) {
		return nil, errors.New("invalid outbound interface name")
	}
	if !options.TunnelPrefix.Addr().Is4() || !options.ServerIP.Is4() {
		return nil, errors.New("server network configuration requires IPv4")
	}
	if options.StateDir == "" {
		options.StateDir = defaultStateDir()
	}
	return &ServerManager{
		options: options,
		runner:  runner,
		path:    filepath.Join(options.StateDir, "server-network-state.json"),
	}, nil
}

func (m *ServerManager) Recover(ctx context.Context) error {
	tx, err := loadTransaction(m.path, m.runner)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return tx.restore(ctx)
}

func (m *ServerManager) Apply(ctx context.Context) error {
	if err := m.Recover(ctx); err != nil {
		return fmt.Errorf("recover server network state: %w", err)
	}
	forward, undo, err := m.plan(ctx)
	if err != nil {
		return err
	}
	tx, err := newTransaction(m.path, m.runner, undo)
	if err != nil {
		return err
	}
	for i, command := range forward {
		if _, err := m.runner.Run(ctx, command.Name, command.Args...); err != nil {
			return errors.Join(err, tx.restore(ctx))
		}
		if err := tx.markApplied(i + 1); err != nil {
			return errors.Join(err, tx.restore(ctx))
		}
	}
	return nil
}

func (m *ServerManager) Restore(ctx context.Context) error {
	tx, err := loadTransaction(m.path, m.runner)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return tx.restore(ctx)
}

func (m *ServerManager) plan(ctx context.Context) ([]Command, []Command, error) {
	prefix := netip.PrefixFrom(m.options.ServerIP, m.options.TunnelPrefix.Bits()).String()
	forward := []Command{
		{Name: "ip", Args: []string{"addr", "add", prefix, "dev", m.options.TUNName}},
		{Name: "ip", Args: []string{"link", "set", "dev", m.options.TUNName, "mtu", strconv.Itoa(m.options.MTU), "up"}},
	}
	undo := []Command{
		{Name: "ip", Args: []string{"addr", "del", prefix, "dev", m.options.TUNName}},
		{Name: "ip", Args: []string{"link", "set", "dev", m.options.TUNName, "down"}},
	}
	if !m.options.ManageNetwork {
		return forward, undo, nil
	}

	ipForward, err := m.runner.Run(ctx, "sysctl", "-n", "net.ipv4.ip_forward")
	if err != nil {
		return nil, nil, err
	}
	ipForward = strings.TrimSpace(ipForward)
	if ipForward != "1" {
		forward = append(forward, Command{Name: "sysctl", Args: []string{"-w", "net.ipv4.ip_forward=1"}})
		undo = append(undo, Command{Name: "sysctl", Args: []string{"-w", "net.ipv4.ip_forward=" + ipForward}})
	}

	comment := "socks5proxy-tunnel-" + m.options.TUNName
	cidr := m.options.TunnelPrefix.String()
	rules := [][]string{
		{"-A", "FORWARD", "-i", m.options.TUNName, "-o", m.options.OutboundInterface, "-s", cidr, "-m", "comment", "--comment", comment, "-j", "ACCEPT"},
		{"-A", "FORWARD", "-i", m.options.OutboundInterface, "-o", m.options.TUNName, "-d", cidr, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-m", "comment", "--comment", comment, "-j", "ACCEPT"},
	}
	for _, args := range rules {
		forward = append(forward, Command{Name: "iptables", Args: args})
		reverse := append([]string(nil), args...)
		reverse[0] = "-D"
		undo = append(undo, Command{Name: "iptables", Args: reverse})
	}
	nat := []string{"-t", "nat", "-A", "POSTROUTING", "-s", cidr, "-o", m.options.OutboundInterface, "-m", "comment", "--comment", comment, "-j", "MASQUERADE"}
	forward = append(forward, Command{Name: "iptables", Args: nat})
	natUndo := append([]string(nil), nat...)
	natUndo[2] = "-D"
	undo = append(undo, Command{Name: "iptables", Args: natUndo})
	return forward, undo, nil
}
