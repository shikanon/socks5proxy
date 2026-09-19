package main

import (
	"context"
	"flag"
	"log"
	"os/signal"
	"syscall"

	"github.com/shikanon/socks5proxy"
	"github.com/shikanon/socks5proxy/internal/tunnel"
	tunnelclient "github.com/shikanon/socks5proxy/internal/tunnel/client"
)

func main() {
	mode := flag.String("mode", "proxy", "Run mode: proxy or tunnel")
	listenAddr := flag.String("local", ":8888", "Input server listen address(Default 8888):")
	serverAddr := flag.String("server", "", "Input server listen address:")
	passwd := flag.String("passwd", "", "Input server proxy password:")
	encrytype := flag.String("type", "random", "Input traffic obfuscation type (simple/random, not secure encryption):")
	recvHTTPProto := flag.String("recv", "http", "Upstream protocol mode: http or socks5 (default http):")
	clientID := flag.String("client-id", "", "Tunnel client identifier")
	tokenFile := flag.String("token-file", "", "Path to tunnel client token file")
	caFile := flag.String("ca", "", "Path to tunnel server CA certificate (default: system roots)")
	serverName := flag.String("server-name", "", "TLS server name (default: server host)")
	dns := flag.String("dns", "", "Tunnel DNS IPv4 address (default: server-provided)")
	linuxDNS := flag.Bool("linux-dns", true, "Manage Linux DNS with systemd-resolved (disable only with externally managed tunnel DNS)")
	mtu := flag.Int("mtu", tunnel.DefaultMTU, "Tunnel MTU (576-1400)")
	stateDir := flag.String("state-dir", "", "Directory for recoverable network state")
	obfs := flag.String("obfs", "none", "TLS-inner tunnel obfuscation: none, simple, or random")
	tunName := flag.String("tun-name", "", "Tunnel interface name")
	flag.Parse()
	if *serverAddr == "" {
		log.Fatal("请输入正确的远程地址")
	}

	switch *mode {
	case "proxy":
		if *passwd == "" {
			log.Fatal("请通过 -passwd 设置一个强密码（不能为空）")
		}
		log.Println("客户端正在启动...")
		log.Println("recv proto:", *recvHTTPProto)
		log.Fatal(socks5proxy.Client(*listenAddr, *serverAddr, *encrytype, *passwd, *recvHTTPProto))
	case "tunnel":
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		if err := tunnelclient.Run(ctx, tunnel.ClientConfig{
			ServerAddr:   *serverAddr,
			ClientID:     *clientID,
			TokenFile:    *tokenFile,
			CAFile:       *caFile,
			ServerName:   *serverName,
			DNS:          *dns,
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
