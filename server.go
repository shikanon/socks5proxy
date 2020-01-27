package socks5proxy

import (
	"log"
	"net"
	"sync"
)

func handleClientRequest(client *net.TCPConn, auth socks5Auth) {
	if client == nil {
		return
	}
	defer client.Close()

	// 初始化一个字符串buff
	buff := make([]byte, 255)

	// 认证协商
	var proto ProtocolVersion
	n, err := auth.DecodeRead(client, buff) //解密
	resp, err := proto.HandleHandshake(buff[0:n])
	auth.EncodeWrite(client, resp) //加密
	if err != nil {
		log.Print(client.RemoteAddr(), err)
		return
	}

	//获取客户端代理的请求
	var request Socks5Resolution
	n, err = auth.DecodeRead(client, buff)
	resp, err = request.LSTRequest(buff[0:n])
	auth.EncodeWrite(client, resp)
	if err != nil {
		log.Print(client.RemoteAddr(), err)
		return
	}

	log.Println(client.RemoteAddr(), request.DSTDOMAIN, request.DSTADDR, request.DSTPORT)

	// 连接真正的远程服务
	dstServer, err := net.DialTCP("tcp", nil, request.RAWADDR)
	if err != nil {
		log.Print(client.RemoteAddr(), err)
		return
	}
	defer dstServer.Close()

	wg := new(sync.WaitGroup)
	wg.Add(2)

	// 本地的内容copy到远程端
	go func() {
		defer wg.Done()
		SecureCopy(client, dstServer, auth.Decrypt)
	}()

	// 远程得到的内容copy到源地址
	go func() {
		defer wg.Done()
		SecureCopy(dstServer, client, auth.Encrypt)
	}()
	wg.Wait()

}

func Server(listenAddrString string, encrytype string, passwd string) {
	//所有客户服务端的流都加密,
	auth, err := CreateAuth(encrytype, passwd)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("你的密码是:%s ,请保管好你的密码", passwd)

	// 监听客户端
	listenAddr, err := net.ResolveTCPAddr("tcp", listenAddrString)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("监听服务器端口: %s ", listenAddrString)

	listener, err := net.ListenTCP("tcp", listenAddr)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			log.Fatal(err)
		}
		go handleClientRequest(conn, auth)
	}
}
