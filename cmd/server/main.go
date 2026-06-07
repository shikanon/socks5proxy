package main

import (
	"flag"
	"github.com/shikanon/socks5proxy"
	"log"
)

func main() {
	listenAddr := flag.String("local", ":18888", "Input server listen address(Default 8888):")
	passwd := flag.String("passwd", "", "Input server proxy password:")
	encrytype := flag.String("type", "random", "Input traffic obfuscation type (simple/random, not secure encryption):")
	flag.Parse()
	if *passwd == "" {
		log.Fatal("请通过 -passwd 设置一个强密码（不能为空）")
	}
	log.Println("服务器正在启动...")
	if err := socks5proxy.Server(*listenAddr, *encrytype, *passwd); err != nil {
		log.Fatal(err)
	}
}
