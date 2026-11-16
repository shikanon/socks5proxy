// Package mesh implements an opt-in, application-scoped service overlay.
// It does not install a TUN, change DNS/routes, or implement a cryptographic primitive.
package mesh

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"regexp"
	"time"
)

const ALPN = "socks5proxy-mesh/1"

var validID = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

type Member struct {
	ID        string   `json:"id"`
	IP        string   `json:"ip"`
	Endpoints []string `json:"endpoints"`
	Ports     []uint16 `json:"ports"`
}
type Service struct {
	Port   uint16   `json:"port"`
	Target string   `json:"target"`
	Allow  []string `json:"allow"`
}
type Config struct {
	Version     int       `json:"version"`
	ID          string    `json:"id"`
	IP          string    `json:"ip"`
	Cert        string    `json:"cert"`
	Key         string    `json:"key"`
	CA          string    `json:"ca"`
	Listen      string    `json:"listen"`
	Endpoint    string    `json:"endpoint"`
	ControlURL  string    `json:"control_url"`
	ControlName string    `json:"control_name"`
	Members     []Member  `json:"members"`
	Services    []Service `json:"services"`
}

func Load(path string) (Config, error) {
	f, e := os.Open(path)
	if e != nil {
		return Config{}, e
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.Size() > 256*1024 {
		return Config{}, errors.New("mesh config exceeds size limit")
	}
	d := json.NewDecoder(io.LimitReader(f, 256*1024+1))
	d.DisallowUnknownFields()
	var c Config
	if e = d.Decode(&c); e != nil {
		return c, e
	}
	var extra any
	if e = d.Decode(&extra); e != io.EOF {
		return c, errors.New("trailing configuration data")
	}
	return c, c.Validate()
}

// Only application virtual addresses are allocated; these are not OS interface addresses.
func validIP(s string) bool {
	ip, e := netip.ParseAddr(s)
	return e == nil && ip.Is4() && netip.MustParsePrefix("100.64.0.0/10").Contains(ip)
}
func endpoint(s string) error {
	h, p, e := net.SplitHostPort(s)
	if e != nil || h == "" || p == "" {
		return errors.New("invalid endpoint")
	}
	n, e := net.LookupPort("tcp", p)
	if e != nil || n < 1 || n > 65535 {
		return errors.New("invalid endpoint port")
	}
	// Port numbers only; do not accept service aliases.
	if fmt.Sprint(n) != p {
		return errors.New("endpoint must use numeric port")
	}
	return nil
}
func (c Config) Validate() error {
	if c.Version != 1 || !validID.MatchString(c.ID) || !validIP(c.IP) {
		return errors.New("invalid mesh version, node identity or virtual IP")
	}
	if c.Cert == "" || c.Key == "" || c.CA == "" {
		return errors.New("mesh requires certificate, private key and CA")
	}
	if len(c.Members) == 0 || len(c.Members) > 256 {
		return errors.New("inventory must have 1..256 members")
	}
	ids := map[string]bool{}
	ips := map[string]bool{}
	self := false
	for _, m := range c.Members {
		if !validID.MatchString(m.ID) || !validIP(m.IP) || ids[m.ID] || ips[m.IP] {
			return errors.New("invalid or duplicate member")
		}
		ids[m.ID] = true
		ips[m.IP] = true
		if len(m.Endpoints) > 8 || len(m.Ports) > 32 {
			return errors.New("member limits exceeded")
		}
		seen := map[string]bool{}
		for _, a := range m.Endpoints {
			if endpoint(a) != nil || seen[a] {
				return errors.New("invalid or duplicate candidate endpoint")
			}
			seen[a] = true
		}
		ports := map[uint16]bool{}
		for _, p := range m.Ports {
			if p == 0 || ports[p] {
				return errors.New("invalid or duplicate service port")
			}
			ports[p] = true
		}
		if m.ID == c.ID {
			if m.IP != c.IP {
				return errors.New("self IP must match inventory")
			}
			self = true
			if c.Endpoint != "" && !seen[c.Endpoint] {
				return errors.New("advertised endpoint is not authorized")
			}
		}
	}
	if !self {
		return errors.New("self must be in inventory")
	}
	if c.Listen != "" {
		h, p, err := net.SplitHostPort(c.Listen)
		if err != nil || h == "" || (p != "0" && endpoint(c.Listen) != nil) {
			return errors.New("invalid listener")
		}
	}
	if len(c.Services) > 32 {
		return errors.New("too many services")
	}
	ports := map[uint16]bool{}
	for _, s := range c.Services {
		if s.Port == 0 || ports[s.Port] || len(s.Allow) == 0 {
			return errors.New("invalid or duplicate service")
		}
		ports[s.Port] = true
		h, _, e := net.SplitHostPort(s.Target)
		ip, e2 := netip.ParseAddr(h)
		if e != nil || e2 != nil || !ip.IsLoopback() || endpoint(s.Target) != nil {
			return errors.New("export target must be a literal loopback TCP address")
		}
		seen := map[string]bool{}
		for _, id := range s.Allow {
			if !ids[id] || seen[id] {
				return errors.New("unknown or duplicate allowed member")
			}
			seen[id] = true
		}
		allowed := false
		for _, m := range c.Members {
			if m.ID == c.ID {
				for _, p := range m.Ports {
					if p == s.Port {
						allowed = true
					}
				}
			}
		}
		if !allowed {
			return errors.New("export port must be authorized by inventory")
		}
	}
	return nil
}

func TLS(c Config, server bool) (*tls.Config, error) {
	cert, e := tls.LoadX509KeyPair(c.Cert, c.Key)
	if e != nil {
		return nil, e
	}
	leaf, e := x509.ParseCertificate(cert.Certificate[0])
	if e != nil {
		return nil, e
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != c.ID {
		return nil, errors.New("certificate SAN must contain exactly the configured node identity")
	}
	roots := x509.NewCertPool()
	pem, e := os.ReadFile(c.CA)
	if e != nil {
		return nil, e
	}
	if !roots.AppendCertsFromPEM(pem) {
		return nil, errors.New("invalid mesh CA")
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, RootCAs: roots, NextProtos: []string{ALPN}}
	if server {
		cfg.ClientCAs = roots
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}
func identity(state tls.ConnectionState) (string, error) {
	if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
		return "", errors.New("unauthenticated peer")
	}
	names := state.PeerCertificates[0].DNSNames
	if len(names) != 1 || !validID.MatchString(names[0]) {
		return "", errors.New("invalid peer certificate identity")
	}
	return names[0], nil
}

const leaseTime = 90 * time.Second
