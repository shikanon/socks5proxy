package tunnel

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strings"
)

const (
	// Leave room in QUIC's minimum 1200-byte UDP payload for a short header,
	// a 20-byte connection ID, packet number, AEAD tag, DATAGRAM frame and
	// our two-byte packet length. Do not depend on path MTU discovery.
	DefaultMTU        = 1150
	DefaultTunnelCIDR = "10.255.0.0/24"
	DefaultDNS        = "1.1.1.1"
)

type ClientConfig struct {
	Transport    string
	ServerAddr   string
	ClientID     string
	TokenFile    string
	CAFile       string
	ServerName   string
	DNS          string
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
	TunnelCIDR        string
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
	case "quic", "tcp", "tcp-plain":
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
	}
	if c.Obfs == "" {
		c.Obfs = "none"
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
	if _, err := NormalizeTransport(c.Transport); err != nil {
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
	if strings.TrimSpace(c.TokenFile) == "" {
		return errors.New("client token file is required")
	}
	if err := validateMTU(c.MTU); err != nil {
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
	if c.MTU == 0 {
		c.MTU = DefaultMTU
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
	if mode != "tcp-plain" && (c.CertFile == "" || c.KeyFile == "") {
		return errors.New("TLS certificate and key files are required")
	}
	if c.TokenFile == "" {
		return errors.New("server token file is required")
	}
	if err := validateMTU(c.MTU); err != nil {
		return err
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
