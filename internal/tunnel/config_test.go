package tunnel

import "testing"

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
		{"", "quic"}, {"quic", "quic"}, {" TCP ", "tcp"}, {"tcp-plain", "tcp-plain"}, {"udp", ""},
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
			needCertificate := tc.want != "tcp-plain"
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
