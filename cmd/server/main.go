package main

import (
	"context"
	"flag"
	"log"
	"os/signal"
	"syscall"
	"time"

	"github.com/shikanon/socks5proxy"
	"github.com/shikanon/socks5proxy/internal/tunnel"
	tunnelserver "github.com/shikanon/socks5proxy/internal/tunnel/server"
)

func main() {
	mode := flag.String("mode", "proxy", "Run mode: proxy or tunnel")
	transportMode := flag.String("transport", "quic", "Tunnel transport: quic, tcp (TLS), or tcp-plain (unencrypted)")
	listenAddr := flag.String("local", ":18888", "Proxy server listen address")
	maxConnections := flag.Int("max-connections", 256, "Maximum simultaneous proxy sessions")
	dialTimeout := flag.Duration("dial-timeout", 10*time.Second, "Proxy destination dial timeout")
	handshakeTimeout := flag.Duration("handshake-timeout", 10*time.Second, "Proxy handshake timeout")
	idleTimeout := flag.Duration("idle-timeout", 5*time.Minute, "Proxy timeout with no traffic in either direction")
	passwd := flag.String("passwd", "", "Input server proxy password:")
	encrytype := flag.String("type", "random", "Input traffic obfuscation type (simple/random, not secure encryption):")
	certFile := flag.String("cert", "", "Path to tunnel TLS certificate")
	keyFile := flag.String("key", "", "Path to tunnel TLS private key")
	tokenFile := flag.String("token-file", "", "Path to client token digest file")
	tunnelCIDR := flag.String("tunnel-cidr", tunnel.DefaultTunnelCIDR, "Tunnel IPv4 CIDR")
	dns := flag.String("dns", tunnel.DefaultDNS, "Tunnel DNS IPv4 address")
	mtu := flag.Int("mtu", tunnel.DefaultMTU, "Tunnel MTU (576-1400)")
	outbound := flag.String("outbound-interface", "", "Linux outbound interface for tunnel NAT")
	manageNetwork := flag.Bool("manage-network", true, "Configure Linux forwarding and NAT")
	obfsAllow := flag.String("obfs-allow", "none,simple,random", "Allowed tunnel obfuscation modes (not encryption)")
	tunName := flag.String("tun-name", "socks5tun0", "Tunnel interface name")
	stateDir := flag.String("state-dir", "", "Directory for recoverable network state")
	flag.Parse()

	switch *mode {
	case "proxy":
		if *passwd == "" {
			log.Fatal("请通过 -passwd 设置非空混淆密码；混淆不提供安全加密")
		}
		log.Println("服务器正在启动...")
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		if err := socks5proxy.ServerContext(ctx, *listenAddr, *encrytype, *passwd, socks5proxy.ProxyOptions{
			MaxConnections: *maxConnections, DialTimeout: *dialTimeout,
			HandshakeTimeout: *handshakeTimeout, IdleTimeout: *idleTimeout,
		}); err != nil {
			log.Fatal(err)
		}
	case "tunnel":
		allowed, err := tunnel.ParseObfsAllow(*obfsAllow)
		if err != nil {
			log.Fatal(err)
		}
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		if err := tunnelserver.Run(ctx, tunnel.ServerConfig{
			Transport:         *transportMode,
			ListenAddr:        *listenAddr,
			CertFile:          *certFile,
			KeyFile:           *keyFile,
			TokenFile:         *tokenFile,
			TunnelCIDR:        *tunnelCIDR,
			DNS:               *dns,
			MTU:               *mtu,
			OutboundInterface: *outbound,
			ManageNetwork:     *manageNetwork,
			ObfsAllow:         allowed,
			TUNName:           *tunName,
			StateDir:          *stateDir,
		}); err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatalf("unsupported mode %q; expected proxy or tunnel", *mode)
	}
}
