package tunnel

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWatchdogConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.json")
	load := func(text string) (ClientConfig, error) {
		t.Helper()
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		return LoadClientConfig(path)
	}
	c, err := load(`{"server":"localhost:443","client_id":"dev","token_file":"dev.token","fallback_timeout":"4s","health_interval":"1s"}`)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.TokenFile != filepath.Join(dir, "dev.token") || c.DisconnectPolicy != "direct" || c.FallbackTimeout != 4*time.Second || c.ReconnectInterval != 5*time.Second {
		t.Fatalf("wrong config: %+v", c)
	}
	for _, text := range []string{`{"unknown":1}`, `{} {}`, `{"fallback_timeout":"0s"}`, `{"health_interval":5}`, `null []`} {
		if _, err := load(text); err == nil {
			t.Fatalf("accepted %s", text)
		}
	}
	for _, mutate := range []func(*ClientConfig){
		func(c *ClientConfig) { c.HealthDNSName = "a..b" },
		func(c *ClientConfig) { c.HealthDNSName = "-a.example" },
		func(c *ClientConfig) { c.HealthDNSName = "bad_name" },
		func(c *ClientConfig) { c.HealthDNSName = "" },
		func(c *ClientConfig) { c.DisconnectPolicy = "allow" },
		func(c *ClientConfig) { c.FallbackTimeout = -1 },
		func(c *ClientConfig) { c.HealthInterval = 3 * time.Second },
		func(c *ClientConfig) { c.ReconnectInterval = -1 },
	} {
		invalid := c
		mutate(&invalid)
		if invalid.Validate() == nil {
			t.Fatalf("accepted %+v", invalid)
		}
	}
}
