package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os/signal"
	"syscall"
	"time"

	"github.com/shikanon/socks5proxy"
	"github.com/shikanon/socks5proxy/internal/buildinfo"
	"github.com/shikanon/socks5proxy/internal/keytable"
	"github.com/shikanon/socks5proxy/internal/tunnel"
	tunnelserver "github.com/shikanon/socks5proxy/internal/tunnel/server"
)

func main() {
	showVersion := flag.Bool("version", false, "Print version and exit")
	mode := flag.String("mode", "proxy", "Run mode: proxy or tunnel")
	transportMode := flag.String("transport", "quic", "Tunnel transport: quic, tcp (TLS), tcp-plain, or tcp-table (daily substitution, no TLS)")
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
	tableFile := flag.String("table-file", keytable.DefaultFile, "Shared token table JSON; tcp-table server generates it if absent")
	tableTokenLength := flag.Int("table-token-length", keytable.DefaultTokenLength, "Generated table token length (8-16 characters)")
	tableClientID := flag.String("client-id", "desktop", "Authorized client identifier for tcp-table")
	tunnelCIDR := flag.String("tunnel-cidr", tunnel.DefaultTunnelCIDR, "Tunnel IPv4 CIDR")
	dns := flag.String("dns", tunnel.DefaultDNS, "Tunnel DNS IPv4 address")
	ipv6 := flag.Bool("ipv6", false, "Enable IPv6 tunnel addresses, forwarding and NAT66")
	tunnelCIDR6 := flag.String("tunnel-cidr6", "", "Tunnel IPv6 prefix (default with IPv6: fd00:5:5::/64)")
	dns6 := flag.String("dns6", "", "Tunnel DNS IPv6 address (default with IPv6: 2606:4700:4700::1111)")
	mtu := flag.Int("mtu", 0, "Tunnel MTU (default: 1150; IPv6: 1280, maximum: 1400)")
	outbound := flag.String("outbound-interface", "", "Linux outbound interface for tunnel NAT")
	manageNetwork := flag.Bool("manage-network", true, "Configure Linux forwarding and NAT")
	obfsAllow := flag.String("obfs-allow", "none,simple,random", "Allowed tunnel obfuscation modes (not encryption)")
	tunName := flag.String("tun-name", "socks5tun0", "Tunnel interface name")
	stateDir := flag.String("state-dir", "", "Directory for recoverable network state")
	flag.Parse()
	if *showVersion {
		fmt.Println(buildinfo.Version)
		return
	}

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
			TableFile:         *tableFile,
			TableTokenLength:  *tableTokenLength,
			TableClientID:     *tableClientID,
			TunnelCIDR:        *tunnelCIDR,
			IPv6:              *ipv6,
			TunnelCIDR6:       *tunnelCIDR6,
			DNSIPv6:           *dns6,
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
