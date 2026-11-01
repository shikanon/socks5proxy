package tunnel

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strings"

	"github.com/shikanon/socks5proxy/internal/keytable"
)

const (
	// Leave room in QUIC's minimum 1200-byte UDP payload for a short header,
	// a 20-byte connection ID, packet number, AEAD tag, DATAGRAM frame and
	// our two-byte packet length. Do not depend on path MTU discovery.
	DefaultMTU         = 1150
	DefaultTunnelCIDR  = "10.255.0.0/24"
	DefaultDNS         = "1.1.1.1"
	DualStackMTU       = 1280
	DefaultTunnelCIDR6 = "fd00:5:5::/64"
	DefaultDNS6        = "2606:4700:4700::1111"
)

type ClientConfig struct {
	Transport    string
	ServerAddr   string
	ClientID     string
	TokenFile    string
	TableFile    string
	CAFile       string
	ServerName   string
	DNS          string
	IPv6         bool
	DNSIPv6      string
	MTU          int
	StateDir     string
	Obfs         string
	TUNName      string
	SkipLinuxDNS bool
}

type ServerConfig struct {
	Transport         string
	ListenAddr        string
	CertFile          string
	KeyFile           string
	TokenFile         string
	TableFile         string
	TableTokenLength  int
	TableClientID     string
	TunnelCIDR        string
	IPv6              bool
	TunnelCIDR6       string
	DNSIPv6           string
	DNS               string
	MTU               int
	OutboundInterface string
	ManageNetwork     bool
	ObfsAllow         map[string]bool
	TUNName           string
	StateDir          string
}

func NormalizeTransport(mode string) (string, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = "quic"
	}
	switch mode {
	case "quic", "tcp", "tcp-plain", "tcp-table":
		return mode, nil
	default:
		return "", fmt.Errorf("unsupported tunnel transport %q", mode)
	}
}

func NormalizeObfs(mode string) (string, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = "none"
	}
	switch mode {
	case "none", "simple", "random":
		return mode, nil
	default:
		return "", fmt.Errorf("unsupported obfs mode %q", mode)
	}
}

func ParseObfsAllow(value string) (map[string]bool, error) {
	if strings.TrimSpace(value) == "" {
		value = "none,simple,random"
	}
	allowed := make(map[string]bool)
	for _, item := range strings.Split(value, ",") {
		mode, err := NormalizeObfs(item)
		if err != nil {
			return nil, err
		}
		allowed[mode] = true
	}
	return allowed, nil
}

func (c *ClientConfig) SetDefaults() {
	if mode, err := NormalizeTransport(c.Transport); err == nil {
		c.Transport = mode
	}
	if c.MTU == 0 {
		c.MTU = DefaultMTU
		if c.IPv6 {
			c.MTU = DualStackMTU
		}
	}
	if c.Obfs == "" {
		c.Obfs = "none"
	}
	if c.Transport == "tcp-table" && c.TableFile == "" {
		c.TableFile = keytable.DefaultFile
	}
	if c.TUNName == "" {
		switch runtime.GOOS {
		case "darwin":
			c.TUNName = "utun"
		case "windows":
			c.TUNName = "Socks5Proxy"
		default:
			c.TUNName = "socks5tun0"
		}
	}
}

func (c ClientConfig) Validate() error {
	mode, err := NormalizeTransport(c.Transport)
	if err != nil {
		return err
	}
	if c.ServerAddr == "" {
		return errors.New("tunnel server address is required")
	}
	if _, _, err := net.SplitHostPort(c.ServerAddr); err != nil {
		return fmt.Errorf("invalid tunnel server address: %w", err)
	}
	if strings.TrimSpace(c.ClientID) == "" {
		return errors.New("client ID is required")
	}
	if mode == "tcp-table" {
		if strings.TrimSpace(c.TableFile) == "" {
			return errors.New("client table file is required")
		}
		if obfs, err := NormalizeObfs(c.Obfs); err != nil || obfs != "none" {
			return errors.New("tcp-table requires -obfs none; daily mapping is built in")
		}
	} else if strings.TrimSpace(c.TokenFile) == "" {
		return errors.New("client token file is required")
	}
	if err := validateMTU(c.MTU); err != nil {
		return err
	}
	if err := validateIPv6Config(c.IPv6, c.DNSIPv6, c.MTU); err != nil {
		return err
	}
	if c.DNS != "" {
		if err := validateIPv4(c.DNS, "DNS"); err != nil {
			return err
		}
	}
	if _, err := NormalizeObfs(c.Obfs); err != nil {
		return err
	}
	return nil
}

func (c *ServerConfig) SetDefaults() error {
	mode, err := NormalizeTransport(c.Transport)
	if err != nil {
		return err
	}
	c.Transport = mode
	if mode == "tcp-table" {
		if c.TableFile == "" {
			c.TableFile = keytable.DefaultFile
		}
		if c.TableTokenLength == 0 {
			c.TableTokenLength = keytable.DefaultTokenLength
		}
		if c.TableClientID == "" {
			c.TableClientID = "desktop"
		}
	}
	if c.MTU == 0 {
		c.MTU = DefaultMTU
		if c.IPv6 {
			c.MTU = DualStackMTU
		}
	}
	if c.IPv6 {
		if c.TunnelCIDR6 == "" {
			c.TunnelCIDR6 = DefaultTunnelCIDR6
		}
		if c.DNSIPv6 == "" {
			c.DNSIPv6 = DefaultDNS6
		}
	}
	if c.TunnelCIDR == "" {
		c.TunnelCIDR = DefaultTunnelCIDR
	}
	if c.DNS == "" {
		c.DNS = DefaultDNS
	}
	if c.TUNName == "" {
		c.TUNName = "socks5tun0"
	}
	if c.ObfsAllow == nil {
		var err error
		c.ObfsAllow, err = ParseObfsAllow("")
		if err != nil {
			return err
		}
	}
	return nil
}

func (c ServerConfig) Validate() error {
	mode, err := NormalizeTransport(c.Transport)
	if err != nil {
		return err
	}
	if c.ListenAddr == "" {
		return errors.New("tunnel listen address is required")
	}
	if _, _, err := net.SplitHostPort(c.ListenAddr); err != nil {
		return fmt.Errorf("invalid tunnel listen address: %w", err)
	}
	if mode != "tcp-plain" && mode != "tcp-table" && (c.CertFile == "" || c.KeyFile == "") {
		return errors.New("TLS certificate and key files are required")
	}
	if mode == "tcp-table" {
		if strings.TrimSpace(c.TableFile) == "" || strings.TrimSpace(c.TableClientID) == "" {
			return errors.New("server table file and table client ID are required")
		}
		if c.TableTokenLength < 8 || c.TableTokenLength > 16 {
			return errors.New("table token length must be between 8 and 16")
		}
		if !c.ObfsAllow["none"] {
			return errors.New("tcp-table requires none in -obfs-allow")
		}
	} else if c.TokenFile == "" {
		return errors.New("server token file is required")
	}
	if err := validateMTU(c.MTU); err != nil {
		return err
	}
	if err := validateIPv6Config(c.IPv6, c.DNSIPv6, c.MTU); err != nil {
		return err
	}
	if c.IPv6 {
		p, err := netip.ParsePrefix(c.TunnelCIDR6)
		if err != nil || !usableIPv6(p.Addr()) || p.Bits() < 64 || p.Bits() > 96 || p != p.Masked() {
			return errors.New("IPv6 tunnel CIDR must be a masked unicast prefix between /64 and /96")
		}
	} else if c.TunnelCIDR6 != "" {
		return errors.New("IPv6 tunnel CIDR requires -ipv6")
	}
	if err := validateIPv4(c.DNS, "DNS"); err != nil {
		return err
	}
	prefix, err := netip.ParsePrefix(c.TunnelCIDR)
	if err != nil || !prefix.Addr().Is4() {
		return errors.New("tunnel CIDR must be a valid IPv4 prefix")
	}
	if prefix.Bits() > 30 {
		return errors.New("tunnel CIDR must provide at least two usable addresses")
	}
	if c.ManageNetwork && strings.TrimSpace(c.OutboundInterface) == "" {
		return errors.New("outbound interface is required when network management is enabled")
	}
	if len(c.ObfsAllow) == 0 {
		return errors.New("at least one obfs mode must be allowed")
	}
	for mode := range c.ObfsAllow {
		if _, err := NormalizeObfs(mode); err != nil {
			return err
		}
	}
	return nil
}

func validateMTU(mtu int) error {
	if mtu < 576 || mtu > 1400 {
		return fmt.Errorf("MTU must be between 576 and 1400, got %d", mtu)
	}
	return nil
}

func validateIPv4(value, field string) error {
	addr, err := netip.ParseAddr(value)
	if err != nil || !addr.Is4() {
		return fmt.Errorf("%s must be a valid IPv4 address", field)
	}
	return nil
}

func usableIPv6(addr netip.Addr) bool {
	return addr.Is6() && !addr.Is4In6() && addr.IsGlobalUnicast() && addr.Zone() == ""
}

func validateIPv6Config(enabled bool, dns string, mtu int) error {
	if !enabled {
		if dns != "" {
			return errors.New("IPv6 DNS requires -ipv6")
		}
		return nil
	}
	if mtu < DualStackMTU {
		return errors.New("IPv6 requires MTU at least 1280")
	}
	if dns != "" {
		addr, err := netip.ParseAddr(dns)
		if err != nil || !usableIPv6(addr) {
			return errors.New("IPv6 DNS must be a valid unicast IPv6 address")
		}
	}
	return nil
}
