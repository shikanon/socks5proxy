package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/shikanon/socks5proxy"
	"github.com/shikanon/socks5proxy/internal/buildinfo"
	"github.com/shikanon/socks5proxy/internal/keytable"
	"github.com/shikanon/socks5proxy/internal/tunnel"
	tunnelclient "github.com/shikanon/socks5proxy/internal/tunnel/client"
	"github.com/shikanon/socks5proxy/routing"
)

func main() {
	showVersion := flag.Bool("version", false, "Print version and exit")
	mode := flag.String("mode", "proxy", "Run mode: proxy or tunnel")
	transportMode := flag.String("transport", "quic", "Tunnel transport: quic, tcp (TLS), tcp-plain, or tcp-table (daily substitution, no TLS)")
	listenAddr := flag.String("local", "127.0.0.1:8888", "Local application proxy listen address")
	serverAddr := flag.String("server", "", "Input server listen address:")
	passwd := flag.String("passwd", "", "Input server proxy password:")
	encrytype := flag.String("type", "random", "Input traffic obfuscation type (simple/random, not secure encryption):")
	recvHTTPProto := flag.String("recv", "http", "Upstream protocol mode: http or socks5 (default http):")
	proxyScope := flag.String("proxy-scope", "all", "Application proxy scope: all or rules (global IPv4 traffic uses -mode tunnel)")
	proxyDomains := flag.String("proxy-domains", "", "Comma-separated website host patterns, e.g. example.com,*.example.org")
	rulesFile := flag.String("rules-file", "", "Website rules file: one host pattern per line, # comments")
	pacListen := flag.String("pac-listen", "", "Optional loopback PAC HTTP listener, e.g. 127.0.0.1:8090")
	maxConnections := flag.Int("max-connections", 256, "Maximum simultaneous proxy sessions")
	dialTimeout := flag.Duration("dial-timeout", 10*time.Second, "Proxy upstream/destination dial timeout")
	handshakeTimeout := flag.Duration("handshake-timeout", 10*time.Second, "Proxy handshake timeout")
	idleTimeout := flag.Duration("idle-timeout", 5*time.Minute, "Proxy timeout with no traffic in either direction")
	clientID := flag.String("client-id", "", "Tunnel client identifier")
	tokenFile := flag.String("token-file", "", "Path to tunnel client token file")
	tableFile := flag.String("table-file", keytable.DefaultFile, "Shared token table JSON copied from the tcp-table server")
	caFile := flag.String("ca", "", "Path to tunnel server CA certificate (default: system roots)")
	serverName := flag.String("server-name", "", "TLS server name (default: server host)")
	dns := flag.String("dns", "", "Tunnel DNS IPv4 address (default: server-provided)")
	linuxDNS := flag.Bool("linux-dns", true, "Manage Linux DNS with systemd-resolved (disable only with externally managed tunnel DNS)")
	ipv6 := flag.Bool("ipv6", false, "Enable global IPv4 and IPv6 tunneling (server must also enable IPv6)")
	dns6 := flag.String("dns6", "", "Tunnel DNS IPv6 address (default: server-provided)")
	mtu := flag.Int("mtu", 0, "Tunnel MTU (default: 1150; IPv6: 1280, maximum: 1400)")
	stateDir := flag.String("state-dir", "", "Directory for recoverable network state")
	obfs := flag.String("obfs", "none", "Tunnel obfuscation (not encryption): none, simple, or random")
	tunName := flag.String("tun-name", "", "Tunnel interface name")
	flag.Parse()
	if *showVersion {
		fmt.Println(buildinfo.Version)
		return
	}
	if *serverAddr == "" {
		log.Fatal("请输入正确的远程地址")
	}

	switch *mode {
	case "proxy":
		if *passwd == "" {
			log.Fatal("请通过 -passwd 设置非空混淆密码；混淆不提供安全加密")
		}
		log.Println("客户端正在启动...")
		log.Println("recv proto:", *recvHTTPProto)
		patterns := strings.Split(*proxyDomains, ",")
		if *rulesFile != "" {
			fileRules, err := routing.Load(*rulesFile)
			if err != nil {
				log.Fatal(err)
			}
			patterns = append(patterns, fileRules.Patterns()...)
		}
		rules, err := routing.New(patterns)
		if err != nil {
			log.Fatal(err)
		}
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		if err := socks5proxy.ClientContext(ctx, *listenAddr, *serverAddr, *encrytype, *passwd, *recvHTTPProto, socks5proxy.ProxyOptions{
			MaxConnections: *maxConnections, DialTimeout: *dialTimeout,
			HandshakeTimeout: *handshakeTimeout, IdleTimeout: *idleTimeout,
			Scope: *proxyScope, Rules: rules, PACListen: *pacListen,
		}); err != nil {
			log.Fatal(err)
		}
	case "tunnel":
		if *proxyScope != "all" || *proxyDomains != "" || *rulesFile != "" || *pacListen != "" {
			log.Fatal("tunnel mode carries global IPv4 traffic; website rules/PAC require -mode proxy -proxy-scope rules")
		}
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		if err := tunnelclient.Run(ctx, tunnel.ClientConfig{
			Transport:    *transportMode,
			ServerAddr:   *serverAddr,
			ClientID:     *clientID,
			TokenFile:    *tokenFile,
			TableFile:    *tableFile,
			CAFile:       *caFile,
			ServerName:   *serverName,
			DNS:          *dns,
			IPv6:         *ipv6,
			DNSIPv6:      *dns6,
			MTU:          *mtu,
			StateDir:     *stateDir,
			Obfs:         *obfs,
			TUNName:      *tunName,
			SkipLinuxDNS: !*linuxDNS,
		}); err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatalf("unsupported mode %q; expected proxy or tunnel", *mode)
	}
}
