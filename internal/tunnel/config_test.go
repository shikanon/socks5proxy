package tunnel

import "testing"

func TestIPv6Config(t *testing.T) {
	c := ClientConfig{IPv6: true, ServerAddr: "[2001:db8::1]:443", ClientID: "desktop", TokenFile: "token"}
	c.SetDefaults()
	if c.MTU != DualStackMTU || c.Validate() != nil {
		t.Fatal("invalid dual-stack defaults", c)
	}
	c.MTU = DefaultMTU
	if c.Validate() == nil {
		t.Fatal("IPv6 requires a minimum MTU of 1280")
	}
	s := ServerConfig{IPv6: true, Transport: "tcp-plain", ListenAddr: ":443", TokenFile: "tokens"}
	if err := s.SetDefaults(); err != nil {
		t.Fatal(err)
	}
	if s.TunnelCIDR6 != DefaultTunnelCIDR6 || s.DNSIPv6 != DefaultDNS6 || s.Validate() != nil {
		t.Fatal("invalid server dual-stack defaults", s)
	}
	for _, cidr := range []string{"::/64", "fe80::/64", "ff00::/64", "fd00::/97", "fd00::/32", "fd00::1/64", "10.0.0.0/24"} {
		s.TunnelCIDR6 = cidr
		if s.Validate() == nil {
			t.Fatal("invalid IPv6 prefix accepted", cidr)
		}
	}
	c.MTU, c.IPv6, c.DNSIPv6 = DefaultMTU, false, DefaultDNS6
	if c.Validate() == nil {
		t.Fatal("IPv6 DNS without IPv6 accepted")
	}
}

func TestClientConfigDefaultsAndValidation(t *testing.T) {
	config := ClientConfig{
		ServerAddr: "vpn.example.com:443",
		ClientID:   "desktop",
		TokenFile:  "/tmp/token",
	}
	config.SetDefaults()
	if config.MTU != DefaultMTU || config.Obfs != "none" || config.Transport != "quic" {
		t.Fatalf("unexpected defaults: %#v", config)
	}
	if config.DNS != "" {
		t.Fatalf("empty DNS must allow the server-provided value, got %q", config.DNS)
	}
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestTransportConfiguration(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  string
	}{
		{"", "quic"}, {"quic", "quic"}, {" TCP ", "tcp"}, {"tcp-plain", "tcp-plain"}, {"tcp-table", "tcp-table"}, {"udp", ""},
	} {
		t.Run(tc.input, func(t *testing.T) {
			got, err := NormalizeTransport(tc.input)
			if got != tc.want || (err != nil) != (tc.want == "") {
				t.Fatal("unexpected normalization", got, err)
			}
			client := ClientConfig{Transport: tc.input, ServerAddr: "localhost:443", ClientID: "test", TokenFile: "token"}
			client.SetDefaults()
			if (client.Validate() != nil) != (tc.want == "") {
				t.Fatal("incorrect client transport validation")
			}
			server := ServerConfig{Transport: tc.input, ListenAddr: ":443", TokenFile: "tokens"}
			if err := server.SetDefaults(); tc.want == "" {
				if err == nil {
					t.Fatal("unknown server transport accepted")
				}
				return
			} else if err != nil || server.Transport != tc.want {
				t.Fatal("incorrect server default", err)
			}
			needCertificate := tc.want != "tcp-plain" && tc.want != "tcp-table"
			if (server.Validate() != nil) != needCertificate {
				t.Fatal("wrong certificate requirement")
			}
			server.CertFile, server.KeyFile = "cert", "key"
			if err := server.Validate(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTableConfig(t *testing.T) {
	client := ClientConfig{Transport: "tcp-table", ServerAddr: "127.0.0.1:443", ClientID: "desktop"}
	client.SetDefaults()
	if err := client.Validate(); err != nil {
		t.Fatal("table mode required a long token or TLS", err)
	}
	client.Obfs = "random"
	if err := client.Validate(); err == nil {
		t.Fatal("double obfuscation accepted")
	}
	server := ServerConfig{Transport: "tcp-table", ListenAddr: ":443"}
	if err := server.SetDefaults(); err != nil {
		t.Fatal(err)
	}
	if err := server.Validate(); err != nil {
		t.Fatal(err)
	}
	server.TableTokenLength = 7
	if err := server.Validate(); err == nil {
		t.Fatal("short table token accepted")
	}
	server.TableTokenLength = 16
	server.ObfsAllow = map[string]bool{"random": true}
	if err := server.Validate(); err == nil {
		t.Fatal("table mode without none accepted")
	}
}

func TestClientConfigRejectsInvalidObfs(t *testing.T) {
	config := ClientConfig{
		ServerAddr: "127.0.0.1:443",
		ClientID:   "desktop",
		TokenFile:  "/tmp/token",
		MTU:        DefaultMTU,
		Obfs:       "legacy",
	}
	if err := config.Validate(); err == nil {
		t.Fatal("expected invalid obfs error")
	}
}

func TestParseObfsAllow(t *testing.T) {
	allowed, err := ParseObfsAllow("none, simple,random")
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"none", "simple", "random"} {
		if !allowed[mode] {
			t.Fatalf("mode %q is not allowed", mode)
		}
	}
}

func TestServerConfigRequiresOutboundInterfaceWhenManagingNetwork(t *testing.T) {
	config := ServerConfig{
		ListenAddr:    ":443",
		CertFile:      "server.crt",
		KeyFile:       "server.key",
		TokenFile:     "tokens",
		TunnelCIDR:    DefaultTunnelCIDR,
		DNS:           DefaultDNS,
		MTU:           DefaultMTU,
		ManageNetwork: true,
		ObfsAllow:     map[string]bool{"none": true},
	}
	if err := config.Validate(); err == nil {
		t.Fatal("expected outbound interface validation error")
	}
}
