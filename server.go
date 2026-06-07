package socks5proxy

import (
	"io"
	"log"
	"net"
	"sync"
)

func handleHandshake(client io.ReadWriter, auth socks5Auth, buff []byte, proto *ProtocolVersion) error {
	n, err := auth.DecodeRead(client, buff)
	if err != nil {
		return err
	}

	resp, err := proto.HandleHandshake(buff[:n])
	if err != nil {
		return err
	}

	_, err = auth.EncodeWrite(client, resp)
	return err
}

func handleRequest(client io.ReadWriter, auth socks5Auth, buff []byte, request *Socks5Resolution) error {
	n, err := auth.DecodeRead(client, buff)
	if err != nil {
		return err
	}

	resp, err := request.LSTRequest(buff[:n])
	if err != nil {
		return err
	}

	_, err = auth.EncodeWrite(client, resp)
	return err
}

func handleClientRequest(client *net.TCPConn, auth socks5Auth) error {
	if client == nil {
		return nil
	}
	defer client.Close()

	// 初始化一个字符串buff
	buff := make([]byte, 255)

	// 认证协商
	var proto ProtocolVersion
	if err := handleHandshake(client, auth, buff, &proto); err != nil {
		return err
	}

	//获取客户端代理的请求
	var request Socks5Resolution
	if err := handleRequest(client, auth, buff, &request); err != nil {
		return err
	}

	log.Println(client.RemoteAddr(), request.DSTDOMAIN, request.DSTADDR, request.DSTPORT)

	// 连接真正的远程服务
	dstServer, err := net.DialTCP("tcp", nil, request.RAWADDR)
	if err != nil {
		return err
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

	return nil
}

func Server(listenAddrString string, encrytype string, passwd string) error {
	//所有客户服务端的流都加密,
	auth, err := CreateAuth(encrytype, passwd)
	if err != nil {
		return err
	}

	// 监听客户端
	listenAddr, err := net.ResolveTCPAddr("tcp", listenAddrString)
	if err != nil {
		return err
	}
	log.Printf("监听服务器端口: %s ", listenAddrString)

	listener, err := net.ListenTCP("tcp", listenAddr)
	if err != nil {
		return err
	}
	defer listener.Close()

	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			log.Print(err)
			continue
		}
		go func(clientConn *net.TCPConn) {
			if err := handleClientRequest(clientConn, auth); err != nil {
				log.Print(clientConn.RemoteAddr(), err)
			}
		}(conn)
	}
}
