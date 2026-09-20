// Package mobile is the gomobile-compatible IPv4 tunnel client.
// Operating-system VPN services own routes and DNS; this package owns transport.
package mobile

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/shikanon/socks5proxy/internal/tunnel"
	"github.com/shikanon/socks5proxy/internal/tunnel/protocol"
)

type config struct {
	ServerAddr string `json:"server_addr"`
	ServerName string `json:"server_name"`
	ClientID   string `json:"client_id"`
	Token      string `json:"token"`
	CAPEM      string `json:"ca_pem"`
	Transport  string `json:"transport"`
	Obfs       string `json:"obfs"`
	MTU        int    `json:"mtu"`
	DNS        string `json:"dns"`
}

func parseConfig(raw string) (config, error) {
	var c config
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		return c, errors.New("invalid configuration JSON")
	}
	c.ServerAddr = strings.TrimSpace(c.ServerAddr)
	c.ClientID = strings.TrimSpace(c.ClientID)
	c.Token = strings.TrimSpace(c.Token)
	var err error
	if c.Transport, err = tunnel.NormalizeTransport(c.Transport); err != nil {
		return c, err
	}
	if c.Obfs, err = tunnel.NormalizeObfs(c.Obfs); err != nil {
		return c, err
	}
	if c.MTU == 0 {
		c.MTU = tunnel.DefaultMTU
	}
	host, port, err := net.SplitHostPort(c.ServerAddr)
	if err != nil || host == "" {
		return c, errors.New("server_addr must be host:port")
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return c, errors.New("server port must be between 1 and 65535")
	}
	if ip, err := netip.ParseAddr(host); err == nil && !ip.Unmap().Is4() {
		return c, errors.New("server endpoint must use IPv4")
	}
	if c.ServerName == "" {
		c.ServerName = host
	}
	if c.ClientID == "" || len(c.Token) < 32 {
		return c, errors.New("client_id and a token of at least 32 characters are required")
	}
	if c.MTU < 576 || c.MTU > 1400 {
		return c, errors.New("MTU must be between 576 and 1400")
	}
	if c.DNS != "" {
		if ip, err := netip.ParseAddr(c.DNS); err != nil || !ip.Is4() {
			return c, errors.New("DNS must be an IPv4 address")
		}
	}
	return c, nil
}

func (c config) tlsConfig() (*tls.Config, error) {
	if c.Transport == "tcp-plain" {
		return nil, nil
	}
	var roots *x509.CertPool
	if strings.TrimSpace(c.CAPEM) != "" {
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM([]byte(c.CAPEM)) {
			return nil, errors.New("ca_pem contains no valid certificate")
		}
	} else {
		var err error
		roots, err = x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("system trust store unavailable; supply ca_pem: %w", err)
		}
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		RootCAs: roots, ServerName: c.ServerName, NextProtos: []string{protocol.ALPN},
	}, nil
}

type parameters struct {
	ClientIPv4   string `json:"client_ipv4"`
	ServerIPv4   string `json:"server_ipv4"`
	DNSIPv4      string `json:"dns_ipv4"`
	EndpointIPv4 string `json:"endpoint_ipv4"`
	MTU          int    `json:"mtu"`
}

func (c config) parameters(response protocol.Message, endpoint string) (parameters, error) {
	p := parameters{response.ClientIPv4, response.ServerIPv4, response.DNSIPv4, endpoint, response.MTU}
	if c.DNS != "" {
		p.DNSIPv4 = c.DNS
	}
	for _, value := range []string{p.ClientIPv4, p.ServerIPv4, p.DNSIPv4} {
		if ip, err := netip.ParseAddr(value); err != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() {
			return p, errors.New("server returned invalid IPv4 tunnel parameters")
		}
	}
	if p.MTU < 576 || p.MTU > c.MTU {
		return p, errors.New("server returned invalid MTU")
	}
	return p, nil
}
