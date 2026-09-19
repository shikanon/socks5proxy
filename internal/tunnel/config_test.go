package tunnel

import "testing"

func TestClientConfigDefaultsAndValidation(t *testing.T) {
	config := ClientConfig{
		ServerAddr: "vpn.example.com:443",
		ClientID:   "desktop",
		TokenFile:  "/tmp/token",
	}
	config.SetDefaults()
	if config.MTU != DefaultMTU || config.Obfs != "none" {
		t.Fatalf("unexpected defaults: %#v", config)
	}
	if config.DNS != "" {
		t.Fatalf("empty DNS must allow the server-provided value, got %q", config.DNS)
	}
	if err := config.Validate(); err != nil {
		t.Fatal(err)
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
