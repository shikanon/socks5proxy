package socks5proxy

import (
	"errors"
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

func readEncryptedFull(reader io.Reader, auth socks5Auth, size int) ([]byte, error) {
	buf := make([]byte, size)
	_, err := io.ReadFull(reader, buf)
	if err != nil {
		return nil, err
	}
	if err := auth.Decrypt(buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func handleRequest(client io.ReadWriter, auth socks5Auth, request *Socks5Resolution) error {
	header, err := readEncryptedFull(client, auth, 4)
	if err != nil {
		return err
	}

	payload := append([]byte{}, header...)
	var remaining int
	switch header[3] {
	case 1:
		remaining = net.IPv4len + 2
	case 3:
		domainLenBytes, err := readEncryptedFull(client, auth, 1)
		if err != nil {
			return err
		}
		if domainLenBytes[0] == 0 {
			return errors.New("域名长度错误")
		}
		payload = append(payload, domainLenBytes...)
		remaining = int(domainLenBytes[0]) + 2
	case 4:
		remaining = net.IPv6len + 2
	default:
		return errors.New("IP地址错误")
	}

	tail, err := readEncryptedFull(client, auth, remaining)
	if err != nil {
		return err
	}
	payload = append(payload, tail...)

	resp, err := request.LSTRequest(payload)
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
	if err := handleRequest(client, auth, &request); err != nil {
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
