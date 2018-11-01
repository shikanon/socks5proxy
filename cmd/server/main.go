package main

import(
	"flag"
	"github.com/shikanon/socks5proxy"
)

func main(){
	listenAddr := flag.String("local", ":18888", "Input server listen address(Default 8888):")
	passwd := flag.String("passwd", "123456", "Input server proxy password:")
	flag.Parse()
	socks5proxy.Server(*listenAddr, *passwd)
}