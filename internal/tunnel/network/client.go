package network

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/shikanon/socks5proxy/internal/tunnel/protocol"
)

type ClientOptions struct {
	TUNName        string
	ClientIP       netip.Addr
	ServerIP       netip.Addr
	TunnelPeer     netip.Addr
	DNS            netip.Addr
	ClientIPv6     netip.Addr
	TunnelPeerIPv6 netip.Addr
	DNSIPv6        netip.Addr
	MTU            int
	StateDir       string
	SkipLinuxDNS   bool
}

type ClientManager struct {
	options ClientOptions
	runner  Runner
	path    string
}

func NewClientManager(options ClientOptions, runner Runner) (*ClientManager, error) {
	if runner == nil {
		runner = ExecRunner{}
	}
	if !options.ClientIP.Is4() || !options.ServerIP.IsValid() || options.ServerIP.IsUnspecified() ||
		options.ServerIP.IsMulticast() || options.ServerIP.Zone() != "" || !options.TunnelPeer.Is4() || !options.DNS.Is4() {
		return nil, errors.New("invalid client network addresses")
	}
	if options.ClientIPv6.IsValid() || options.TunnelPeerIPv6.IsValid() || options.DNSIPv6.IsValid() {
		msg := protocol.Message{IPv6: true, ClientIPv6: options.ClientIPv6.String(), ServerIPv6: options.TunnelPeerIPv6.String(), MTU: options.MTU}
		if options.DNSIPv6.IsValid() {
			msg.DNSIPv6 = options.DNSIPv6.String()
		}
		if _, _, _, err := protocol.ValidateIPv6Parameters(msg, true); err != nil {
			return nil, err
		}
	}
	if !safeInterfaceName(options.TUNName) {
		return nil, errors.New("invalid TUN interface name")
	}
	if options.StateDir == "" {
		options.StateDir = defaultStateDir()
	}
	return &ClientManager{
		options: options,
		runner:  runner,
		path:    filepath.Join(options.StateDir, "network-state.json"),
	}, nil
}

func RecoverClientState(ctx context.Context, stateDir string, runner Runner) error {
	if runner == nil {
		runner = ExecRunner{}
	}
	if stateDir == "" {
		stateDir = defaultStateDir()
	}
	path := filepath.Join(stateDir, "network-state.json")
	tx, err := loadTransaction(path, runner)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return tx.restore(ctx)
}

func (m *ClientManager) Recover(ctx context.Context) error {
	tx, err := loadTransaction(m.path, m.runner)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return tx.restore(ctx)
}

func (m *ClientManager) Apply(ctx context.Context) error {
	if _, err := os.Stat(m.path); err == nil {
		return errors.New("network transaction already exists; recover it before applying")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
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
			rollbackErr := tx.restore(ctx)
			return errors.Join(err, rollbackErr)
		}
		if err := tx.markApplied(i + 1); err != nil {
			rollbackErr := tx.restore(ctx)
			return errors.Join(err, rollbackErr)
		}
	}
	return nil
}

func (m *ClientManager) Restore(ctx context.Context) error {
	tx, err := loadTransaction(m.path, m.runner)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return tx.restore(ctx)
}

func (m *ClientManager) plan(ctx context.Context) ([]Command, []Command, error) {
	switch runtime.GOOS {
	case "darwin":
		return m.planDarwin(ctx)
	case "windows":
		return m.planWindows(ctx)
	case "linux":
		return m.planLinux(ctx)
	default:
		return nil, nil, fmt.Errorf("global tunnel networking is unsupported on %s", runtime.GOOS)
	}
}

func (m *ClientManager) planDarwin(ctx context.Context) ([]Command, []Command, error) {
	routeArgs := []string{"-n", "get", "default"}
	if m.options.ServerIP.Is6() {
		routeArgs = []string{"-n", "get", "-inet6", "default"}
	}
	routeOutput, err := m.runner.Run(ctx, "route", routeArgs...)
	if err != nil {
		return nil, nil, err
	}
	gateway := fieldValue(routeOutput, "gateway")
	physical := fieldValue(routeOutput, "interface")
	gatewayAddr, parseErr := netip.ParseAddr(gateway)
	if parseErr != nil || gatewayAddr.Is6() != m.options.ServerIP.Is6() || !safeInterfaceName(physical) {
		return nil, nil, errors.New("could not determine the macOS default route")
	}
	serviceOutput, err := m.runner.Run(ctx, "networksetup", "-listnetworkserviceorder")
	if err != nil {
		return nil, nil, err
	}
	service := darwinServiceForInterface(serviceOutput, physical)
	if service == "" {
		return nil, nil, fmt.Errorf("could not find network service for %s", physical)
	}
	oldDNSOutput, err := m.runner.Run(ctx, "networksetup", "-getdnsservers", service)
	if err != nil {
		return nil, nil, err
	}
	oldDNS := strings.Fields(strings.TrimSpace(oldDNSOutput))
	restoreDNS := []string{"-setdnsservers", service, "Empty"}
	if len(oldDNS) > 0 && !strings.HasPrefix(oldDNSOutput, "There aren't any") {
		restoreDNS = append([]string{"-setdnsservers", service}, oldDNS...)
	}

	forward := []Command{
		{Name: "ifconfig", Args: []string{m.options.TUNName, "inet", m.options.ClientIP.String(), m.options.TunnelPeer.String(), "mtu", strconv.Itoa(m.options.MTU), "up"}},
		{Name: "route", Args: []string{"-n", "add", "-host", m.options.ServerIP.String(), gateway}},
		{Name: "route", Args: []string{"-n", "add", "-net", "0.0.0.0/1", "-interface", m.options.TUNName}},
		{Name: "route", Args: []string{"-n", "add", "-net", "128.0.0.0/1", "-interface", m.options.TUNName}},
		{Name: "networksetup", Args: []string{"-setdnsservers", service, m.options.DNS.String()}},
		{Name: "route", Args: []string{"-n", "add", "-inet6", "-net", "2000::", "-prefixlen", "3", "-reject", "::1"}},
		{Name: "route", Args: []string{"-n", "add", "-inet6", "-net", "fc00::", "-prefixlen", "7", "-reject", "::1"}},
	}
	undo := []Command{
		{Name: "ifconfig", Args: []string{m.options.TUNName, "down"}},
		{Name: "route", Args: []string{"-n", "delete", "-host", m.options.ServerIP.String()}},
		{Name: "route", Args: []string{"-n", "delete", "-net", "0.0.0.0/1"}},
		{Name: "route", Args: []string{"-n", "delete", "-net", "128.0.0.0/1"}},
		{Name: "networksetup", Args: restoreDNS},
		{Name: "route", Args: []string{"-n", "delete", "-inet6", "-net", "2000::", "-prefixlen", "3"}},
		{Name: "route", Args: []string{"-n", "delete", "-inet6", "-net", "fc00::", "-prefixlen", "7"}},
	}
	forward[4].Args = append([]string{"-setdnsservers", service}, m.dnsServers()...)
	if m.options.ServerIP.Is6() {
		forward[1].Args = []string{"-n", "add", "-inet6", "-host", m.options.ServerIP.String(), gateway}
		undo[1].Args = []string{"-n", "delete", "-inet6", "-host", m.options.ServerIP.String()}
	}
	if m.options.ClientIPv6.IsValid() {
		forward, undo = forward[:5], undo[:5]
		forward = append(forward,
			Command{Name: "ifconfig", Args: []string{m.options.TUNName, "inet6", m.options.ClientIPv6.String(), "prefixlen", "128", "alias"}},
			Command{Name: "route", Args: []string{"-n", "add", "-inet6", "-net", "::/1", "-interface", m.options.TUNName}},
			Command{Name: "route", Args: []string{"-n", "add", "-inet6", "-net", "8000::/1", "-interface", m.options.TUNName}},
		)
		undo = append(undo,
			Command{Name: "ifconfig", Args: []string{m.options.TUNName, "inet6", m.options.ClientIPv6.String(), "-alias"}},
			Command{Name: "route", Args: []string{"-n", "delete", "-inet6", "-net", "::/1"}},
			Command{Name: "route", Args: []string{"-n", "delete", "-inet6", "-net", "8000::/1"}},
		)
	}
	return forward, undo, nil
}

func (m *ClientManager) planWindows(ctx context.Context) ([]Command, []Command, error) {
	routeQuery := "$r=Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1; $d=@((Get-DnsClientServerAddress -InterfaceIndex $r.InterfaceIndex).ServerAddresses); [pscustomobject]@{InterfaceIndex=$r.InterfaceIndex;NextHop=$r.NextHop;DNS=$d} | ConvertTo-Json -Compress"
	hostPrefix := m.options.ServerIP.String() + "/32"
	if m.options.ServerIP.Is6() {
		hostPrefix = m.options.ServerIP.String() + "/128"
		routeQuery = strings.Replace(routeQuery, "-AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0'", "-AddressFamily IPv6 -DestinationPrefix '::/0'", 1)
	}
	output, err := m.runner.Run(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", routeQuery)
	if err != nil {
		return nil, nil, err
	}
	var route struct {
		InterfaceIndex int      `json:"InterfaceIndex"`
		NextHop        string   `json:"NextHop"`
		DNS            []string `json:"DNS"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &route); err != nil {
		return nil, nil, fmt.Errorf("decode Windows default route: %w", err)
	}
	if route.InterfaceIndex <= 0 {
		return nil, nil, errors.New("could not determine the Windows default route")
	}
	if addr, err := netip.ParseAddr(route.NextHop); err != nil || addr.Is6() != m.options.ServerIP.Is6() {
		return nil, nil, errors.New("windows default gateway family does not match endpoint")
	}
	tunName := psQuote(m.options.TUNName)
	blockName := psQuote("Socks5Proxy IPv6 block")
	var oldMTU struct{ IPv4, IPv6 int }
	if m.options.ClientIPv6.IsValid() {
		script := fmt.Sprintf("[pscustomobject]@{IPv4=(Get-NetIPInterface -InterfaceAlias %s -AddressFamily IPv4).NlMtuBytes;IPv6=(Get-NetIPInterface -InterfaceAlias %s -AddressFamily IPv6).NlMtuBytes} | ConvertTo-Json -Compress", tunName, tunName)
		output, err := m.runner.Run(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
		if err != nil {
			return nil, nil, err
		}
		if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &oldMTU); err != nil || oldMTU.IPv4 < 576 || oldMTU.IPv6 < 1280 {
			return nil, nil, errors.New("could not read Windows TUN MTU")
		}
	}
	restorePhysicalDNS := fmt.Sprintf("Set-DnsClientServerAddress -InterfaceIndex %d -ResetServerAddresses -ErrorAction SilentlyContinue", route.InterfaceIndex)
	if len(route.DNS) > 0 {
		restorePhysicalDNS = fmt.Sprintf("Set-DnsClientServerAddress -InterfaceIndex %d -ServerAddresses %s -ErrorAction SilentlyContinue", route.InterfaceIndex, psArray(route.DNS))
	}
	forwardScripts := []string{
		fmt.Sprintf("New-NetIPAddress -InterfaceAlias %s -IPAddress %s -PrefixLength 32 -PolicyStore ActiveStore -ErrorAction Stop", tunName, psQuote(m.options.ClientIP.String())),
		fmt.Sprintf("New-NetRoute -DestinationPrefix %s -InterfaceIndex %d -NextHop %s -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction Stop", psQuote(hostPrefix), route.InterfaceIndex, psQuote(route.NextHop)),
		fmt.Sprintf("New-NetRoute -DestinationPrefix '0.0.0.0/1' -InterfaceAlias %s -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction Stop", tunName),
		fmt.Sprintf("New-NetRoute -DestinationPrefix '128.0.0.0/1' -InterfaceAlias %s -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction Stop", tunName),
		fmt.Sprintf("Set-DnsClientServerAddress -InterfaceAlias %s -ServerAddresses %s -ErrorAction Stop", tunName, psArray(m.dnsServers())),
		fmt.Sprintf("Set-DnsClientServerAddress -InterfaceIndex %d -ServerAddresses %s -ErrorAction Stop", route.InterfaceIndex, psArray(m.dnsServers())),
		fmt.Sprintf("New-NetFirewallRule -DisplayName %s -Direction Outbound -Action Block -RemoteAddress %s -ErrorAction Stop", blockName, psArray(ipv6BlockRanges(m.options.ServerIP))),
	}
	undoScripts := []string{
		fmt.Sprintf("Remove-NetIPAddress -InterfaceAlias %s -IPAddress %s -Confirm:$false -ErrorAction SilentlyContinue", tunName, psQuote(m.options.ClientIP.String())),
		fmt.Sprintf("Remove-NetRoute -DestinationPrefix %s -InterfaceIndex %d -Confirm:$false -ErrorAction SilentlyContinue", psQuote(hostPrefix), route.InterfaceIndex),
		fmt.Sprintf("Remove-NetRoute -DestinationPrefix '0.0.0.0/1' -InterfaceAlias %s -Confirm:$false -ErrorAction SilentlyContinue", tunName),
		fmt.Sprintf("Remove-NetRoute -DestinationPrefix '128.0.0.0/1' -InterfaceAlias %s -Confirm:$false -ErrorAction SilentlyContinue", tunName),
		fmt.Sprintf("Set-DnsClientServerAddress -InterfaceAlias %s -ResetServerAddresses -ErrorAction SilentlyContinue", tunName),
		restorePhysicalDNS,
		fmt.Sprintf("Remove-NetFirewallRule -DisplayName %s -ErrorAction SilentlyContinue", blockName),
	}
	if m.options.ClientIPv6.IsValid() {
		forwardScripts, undoScripts = forwardScripts[:6], undoScripts[:6]
		forwardScripts = append(forwardScripts,
			fmt.Sprintf("New-NetIPAddress -InterfaceAlias %s -IPAddress %s -PrefixLength 128 -PolicyStore ActiveStore -ErrorAction Stop", tunName, psQuote(m.options.ClientIPv6.String())),
			fmt.Sprintf("New-NetRoute -DestinationPrefix '::/1' -InterfaceAlias %s -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction Stop", tunName),
			fmt.Sprintf("New-NetRoute -DestinationPrefix '8000::/1' -InterfaceAlias %s -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction Stop", tunName),
			fmt.Sprintf("Set-NetIPInterface -InterfaceAlias %s -AddressFamily IPv6 -NlMtuBytes %d -ErrorAction Stop", tunName, m.options.MTU),
			fmt.Sprintf("Set-NetIPInterface -InterfaceAlias %s -AddressFamily IPv4 -NlMtuBytes %d -ErrorAction Stop", tunName, m.options.MTU),
		)
		undoScripts = append(undoScripts,
			fmt.Sprintf("Remove-NetIPAddress -InterfaceAlias %s -IPAddress %s -Confirm:$false -ErrorAction SilentlyContinue", tunName, psQuote(m.options.ClientIPv6.String())),
			fmt.Sprintf("Remove-NetRoute -DestinationPrefix '::/1' -InterfaceAlias %s -Confirm:$false -ErrorAction SilentlyContinue", tunName),
			fmt.Sprintf("Remove-NetRoute -DestinationPrefix '8000::/1' -InterfaceAlias %s -Confirm:$false -ErrorAction SilentlyContinue", tunName),
			fmt.Sprintf("Set-NetIPInterface -InterfaceAlias %s -AddressFamily IPv6 -NlMtuBytes %d -ErrorAction SilentlyContinue", tunName, oldMTU.IPv6),
			fmt.Sprintf("Set-NetIPInterface -InterfaceAlias %s -AddressFamily IPv4 -NlMtuBytes %d -ErrorAction SilentlyContinue", tunName, oldMTU.IPv4),
		)
	}
	return powershellCommands(forwardScripts), powershellCommands(undoScripts), nil
}

func (m *ClientManager) planLinux(ctx context.Context) ([]Command, []Command, error) {
	family := "-4"
	hostPrefix := m.options.ServerIP.String() + "/32"
	if m.options.ServerIP.Is6() {
		family, hostPrefix = "-6", m.options.ServerIP.String()+"/128"
	}
	output, err := m.runner.Run(ctx, "ip", family, "route", "show", "default")
	if err != nil {
		return nil, nil, err
	}
	fields := strings.Fields(output)
	gateway, physical := valueAfter(fields, "via"), valueAfter(fields, "dev")
	gatewayAddr, parseErr := netip.ParseAddr(gateway)
	if parseErr != nil || gatewayAddr.Is6() != m.options.ServerIP.Is6() || !safeInterfaceName(physical) {
		return nil, nil, errors.New("could not determine the Linux default route")
	}
	if !m.options.SkipLinuxDNS {
		if _, err := m.runner.Run(ctx, "resolvectl", "status"); err != nil {
			return nil, nil, fmt.Errorf("tunnel DNS on Linux requires systemd-resolved; use -linux-dns=false only with externally managed tunnel DNS: %w", err)
		}
		resolvConf, err := m.runner.Run(ctx, "cat", "/etc/resolv.conf")
		if err != nil {
			return nil, nil, err
		}
		stub := false
		for _, line := range strings.Split(resolvConf, "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 || fields[0] != "nameserver" {
				continue
			}
			if fields[1] != "127.0.0.53" && fields[1] != "127.0.0.54" {
				return nil, nil, errors.New("tunnel DNS on Linux requires /etc/resolv.conf to use only the systemd-resolved stub; use -linux-dns=false only with externally managed tunnel DNS")
			}
			stub = true
		}
		if !stub {
			return nil, nil, errors.New("no systemd-resolved stub nameserver in /etc/resolv.conf")
		}
	}
	forward := []Command{
		{Name: "ip", Args: []string{"addr", "add", m.options.ClientIP.String() + "/32", "peer", m.options.TunnelPeer.String(), "dev", m.options.TUNName}},
		{Name: "ip", Args: []string{"link", "set", "dev", m.options.TUNName, "mtu", strconv.Itoa(m.options.MTU), "up"}},
		{Name: "ip", Args: []string{"route", "add", m.options.ServerIP.String() + "/32", "via", gateway, "dev", physical}},
		{Name: "ip", Args: []string{"route", "add", "0.0.0.0/1", "dev", m.options.TUNName}},
		{Name: "ip", Args: []string{"route", "add", "128.0.0.0/1", "dev", m.options.TUNName}},
	}
	undo := []Command{
		{Name: "ip", Args: []string{"addr", "del", m.options.ClientIP.String() + "/32", "peer", m.options.TunnelPeer.String(), "dev", m.options.TUNName}},
		{Name: "ip", Args: []string{"link", "set", "dev", m.options.TUNName, "down"}},
		{Name: "ip", Args: []string{"route", "del", m.options.ServerIP.String() + "/32"}},
		{Name: "ip", Args: []string{"route", "del", "0.0.0.0/1"}},
		{Name: "ip", Args: []string{"route", "del", "128.0.0.0/1"}},
	}
	if m.options.ServerIP.Is6() {
		forward[2].Args = []string{"-6", "route", "add", hostPrefix, "via", gateway, "dev", physical}
		undo[2].Args = []string{"-6", "route", "del", hostPrefix}
	}
	if m.options.ClientIPv6.IsValid() {
		forward = append(forward,
			Command{Name: "ip", Args: []string{"-6", "addr", "add", m.options.ClientIPv6.String() + "/128", "dev", m.options.TUNName, "nodad"}},
			Command{Name: "ip", Args: []string{"-6", "route", "add", "::/1", "dev", m.options.TUNName}},
			Command{Name: "ip", Args: []string{"-6", "route", "add", "8000::/1", "dev", m.options.TUNName}},
		)
		undo = append(undo,
			Command{Name: "ip", Args: []string{"-6", "addr", "del", m.options.ClientIPv6.String() + "/128", "dev", m.options.TUNName}},
			Command{Name: "ip", Args: []string{"-6", "route", "del", "::/1"}},
			Command{Name: "ip", Args: []string{"-6", "route", "del", "8000::/1"}},
		)
	}
	if !m.options.SkipLinuxDNS {
		// The TUN may already be gone after a crash. Never revert the physical
		// interface; resolved automatically removes settings for deleted links.
		restoreDNS := Command{Name: "sh", Args: []string{"-c",
			`if [ -e "/sys/class/net/$1" ]; then resolvectl revert "$1" || exit; fi; resolvectl flush-caches`,
			"socks5proxy-dns-restore", m.options.TUNName}}
		forward = append(forward,
			Command{Name: "resolvectl", Args: append([]string{"dns", m.options.TUNName}, m.dnsServers()...)},
			Command{Name: "resolvectl", Args: []string{"domain", m.options.TUNName, "~."}},
			Command{Name: "resolvectl", Args: []string{"flush-caches"}},
		)
		undo = append(undo, restoreDNS, restoreDNS,
			Command{Name: "resolvectl", Args: []string{"flush-caches"}},
		)
	}
	return forward, undo, nil
}

func (m *ClientManager) dnsServers() []string {
	servers := []string{m.options.DNS.String()}
	if m.options.DNSIPv6.IsValid() {
		servers = append(servers, m.options.DNSIPv6.String())
	}
	return servers
}

// A Windows block rule overrides allow rules. Exclude an IPv6 outer endpoint
// from the blocked ranges so IPv4-only tunnels can also use an IPv6 carrier.
func ipv6BlockRanges(endpoint netip.Addr) []string {
	var ranges []string
	for _, cidr := range []string{"2000::/3", "fc00::/7"} {
		prefix := netip.MustParsePrefix(cidr)
		if !prefix.Contains(endpoint) {
			ranges = append(ranges, cidr)
			continue
		}
		for bit := prefix.Bits(); bit < 128; bit++ {
			raw := endpoint.As16()
			raw[bit/8] ^= 1 << (7 - bit%8)
			ranges = append(ranges, netip.PrefixFrom(netip.AddrFrom16(raw), bit+1).Masked().String())
		}
	}
	return ranges
}

func defaultStateDir() string {
	switch runtime.GOOS {
	case "windows":
		if value := os.Getenv("ProgramData"); value != "" {
			return filepath.Join(value, "socks5proxy")
		}
		return `C:\ProgramData\socks5proxy`
	default:
		return "/var/run/socks5proxy"
	}
}

func fieldValue(output, key string) string {
	for _, line := range strings.Split(output, "\n") {
		name, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if ok && strings.TrimSpace(name) == key {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func darwinServiceForInterface(output, iface string) string {
	service := ""
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "(") && !strings.Contains(line, "Hardware Port:") {
			if index := strings.Index(line, ") "); index >= 0 {
				service = strings.TrimSpace(line[index+2:])
			}
			continue
		}
		if strings.Contains(line, "Device: "+iface+")") {
			return strings.TrimPrefix(service, "*")
		}
	}
	return ""
}

func valueAfter(fields []string, key string) string {
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == key {
			return fields[i+1]
		}
	}
	return ""
}

var interfaceNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

func safeInterfaceName(name string) bool {
	return name != "" && interfaceNamePattern.MatchString(name)
}

func psQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func psArray(values []string) string {
	quoted := make([]string, 0, len(values))
	for _, value := range values {
		quoted = append(quoted, psQuote(value))
	}
	return "@(" + strings.Join(quoted, ",") + ")"
}

func powershellCommands(scripts []string) []Command {
	commands := make([]Command, 0, len(scripts))
	for _, script := range scripts {
		commands = append(commands, Command{
			Name: "powershell.exe",
			Args: []string{"-NoProfile", "-NonInteractive", "-Command", script},
		})
	}
	return commands
}
