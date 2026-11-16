// mesh adds application-scoped virtual services without changing system networking.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/shikanon/socks5proxy"
	"github.com/shikanon/socks5proxy/internal/mesh"
)

func run() error {
	flags := flag.NewFlagSet("mesh", flag.ContinueOnError)
	config := flags.String("config", "", "Mesh configuration file")
	examplesDir := flags.String("examples-dir", "", "Existing empty directory for non-secret example configs")
	local := flags.String("local", "127.0.0.1:18898", "Opt-in loopback HTTP proxy listener")
	remote := flags.String("server", "", "Virtual service address, e.g. 100.64.0.2:8080")
	secret := flags.String("secret-file", "", "Private existing random-proxy secret file")
	controlListen := flags.String("control-listen", "127.0.0.1:18443", "Explicit HTTPS directory listener")
	if len(os.Args) < 2 {
		return fmt.Errorf("usage: mesh node|proxy|control|peers|check -config FILE")
	}
	action := os.Args[1]
	if e := flags.Parse(os.Args[2:]); e != nil {
		return e
	}
	if action == "examples" {
		return mesh.WriteExamples(*examplesDir)
	}
	c, e := mesh.Load(*config)
	if e != nil {
		return e
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	switch action {
	case "check":
		if _, e = mesh.TLS(c, false); e != nil {
			return e
		}
		fmt.Println("mesh configuration and node identity valid; no networking changes")
		return nil
	case "control":
		tlsConfig, e := mesh.ControlTLS(c)
		if e != nil {
			return e
		}
		server := &http.Server{Addr: *controlListen, Handler: mesh.NewDirectory(c.Members).Handler(), TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}
		go func() {
			<-ctx.Done()
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = server.Shutdown(shutdown)
		}()
		e = server.ListenAndServeTLS(c.Cert, c.Key)
		if e == http.ErrServerClosed {
			return nil
		}
		return e
	case "peers":
		rows, e := mesh.Peers(ctx, c)
		if e != nil {
			return e
		}
		for _, r := range rows {
			fmt.Printf("%s %s ports=%v lease-until=%s\n", r.ID, r.IP, r.Ports, r.Expires.Format(time.RFC3339))
		}
		return nil
	case "node", "proxy":
		node, e := mesh.NewNode(c)
		if e != nil {
			return e
		}
		defer node.Close()
		if action == "node" {
			return node.Run(ctx)
		}
		h, _, e := net.SplitHostPort(*local)
		ip := net.ParseIP(h)
		if e != nil || ip == nil || !ip.IsLoopback() {
			return fmt.Errorf("HTTP proxy must bind literal loopback")
		}
		if *remote == "" || *secret == "" {
			return fmt.Errorf("proxy requires virtual -server and -secret-file")
		}
		value, e := os.ReadFile(*secret)
		if e != nil {
			return e
		}
		password := strings.TrimSpace(string(value))
		if password == "" {
			return fmt.Errorf("empty proxy secret")
		}
		if c.ControlURL != "" {
			if e = node.Refresh(ctx); e != nil {
				return e
			}
		}
		runCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		result := make(chan error, 2)
		go func() { e := node.Run(runCtx); result <- e; cancel() }()
		go func() {
			e := socks5proxy.ClientContext(runCtx, *local, *remote, "random", password, "http", socks5proxy.ProxyOptions{UpstreamDialContext: node.DialContext})
			result <- e
			cancel()
		}()
		first := <-result
		second := <-result
		if first != nil {
			return first
		}
		return second
	default:
		return fmt.Errorf("unknown action")
	}
}
func main() {
	if e := run(); e != nil {
		log.Fatal(e)
	}
}
