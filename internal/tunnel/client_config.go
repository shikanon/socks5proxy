package tunnel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// LoadClientConfig accepts duration strings and resolves paths beside the config.
// Validation is separate so status/recovery can use an incomplete configuration.
func LoadClientConfig(path string) (ClientConfig, error) {
	var file struct {
		Transport         string `json:"transport"`
		ServerAddr        string `json:"server"`
		ClientID          string `json:"client_id"`
		TokenFile         string `json:"token_file"`
		TableFile         string `json:"table_file"`
		CAFile            string `json:"ca"`
		ServerName        string `json:"server_name"`
		DNS               string `json:"dns"`
		IPv6              bool   `json:"ipv6"`
		DNSIPv6           string `json:"dns6"`
		MTU               int    `json:"mtu"`
		StateDir          string `json:"state_dir"`
		Obfs              string `json:"obfs"`
		TUNName           string `json:"tun_name"`
		SkipLinuxDNS      bool   `json:"skip_linux_dns"`
		DisconnectPolicy  string `json:"disconnect_policy"`
		FallbackTimeout   string `json:"fallback_timeout"`
		HealthInterval    string `json:"health_interval"`
		HealthDNSName     string `json:"health_dns_name"`
		ReconnectInterval string `json:"reconnect_interval"`
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ClientConfig{}, err
	}
	if len(data) > 64*1024 {
		return ClientConfig{}, fmt.Errorf("client config exceeds 64 KiB")
	}
	if trimmed := bytes.TrimSpace(data); len(trimmed) == 0 || trimmed[0] != '{' {
		return ClientConfig{}, fmt.Errorf("client config must be a JSON object")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&file); err != nil {
		return ClientConfig{}, fmt.Errorf("decode client config: %w", err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return ClientConfig{}, fmt.Errorf("client config must contain one JSON object")
	}
	c := ClientConfig{Transport: file.Transport, ServerAddr: file.ServerAddr, ClientID: file.ClientID,
		TokenFile: file.TokenFile, TableFile: file.TableFile, CAFile: file.CAFile, ServerName: file.ServerName,
		DNS: file.DNS, IPv6: file.IPv6, DNSIPv6: file.DNSIPv6, MTU: file.MTU, StateDir: file.StateDir,
		Obfs: file.Obfs, TUNName: file.TUNName, SkipLinuxDNS: file.SkipLinuxDNS, DisconnectPolicy: file.DisconnectPolicy,
		HealthDNSName: file.HealthDNSName}
	for _, item := range []struct {
		name, value string
		dest        *time.Duration
	}{
		{"fallback_timeout", file.FallbackTimeout, &c.FallbackTimeout},
		{"health_interval", file.HealthInterval, &c.HealthInterval},
		{"reconnect_interval", file.ReconnectInterval, &c.ReconnectInterval},
	} {
		if item.value == "" {
			continue
		}
		d, err := time.ParseDuration(item.value)
		if err != nil || d <= 0 {
			return ClientConfig{}, fmt.Errorf("invalid %s duration %q", item.name, item.value)
		}
		*item.dest = d
	}
	c.SetDefaults()
	abs, err := filepath.Abs(path)
	if err != nil {
		return ClientConfig{}, err
	}
	for _, p := range []*string{&c.TokenFile, &c.TableFile, &c.CAFile, &c.StateDir} {
		if *p != "" && !filepath.IsAbs(*p) {
			*p = filepath.Join(filepath.Dir(abs), *p)
		}
	}
	return c, nil
}
