package socks5proxy

import (
	"bytes"
	"encoding/binary"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
)

type TcpClient struct {
	conn   *net.TCPConn
	server *net.TCPAddr
}

func handleProxyRequest(localClient *net.TCPConn, serverAddr *net.TCPAddr, auth socks5Auth, recvHTTPProto string) {

	// 远程连接IO
	dstServer, err := net.DialTCP("tcp", nil, serverAddr)
	if err != nil {
		log.Print("远程服务器地址连接错误!!!")
		log.Print(err)
		return
	}
	defer dstServer.Close()

	defer localClient.Close()

	// 和远程端建立安全信道
	wg := new(sync.WaitGroup)
	wg.Add(2)

	if recvHTTPProto == "http" {
		// socket5请求认证协商
		// 第一阶段协议版本及认证方式
		auth.EncodeWrite(dstServer, []byte{0x05, 0x01, 0x00})
		resp := make([]byte, 1024)
		n, err := auth.DecodeRead(dstServer, resp)
		if err != nil {
			log.Fatal(err)
			return
		}
		if n == 0 {
			log.Fatal("协议错误,服务器返回为空")
			return
		}
		if resp[1] == 0x00 && n == 2 {
			log.Print("success")
		} else {
			log.Fatal("协议错误，连接失败")
			return
		}
		// 第二阶段根据认证方式执行对应的认证，由于采用无密码格式，这里省略验证
		// 第三阶段请求信息
		// VER, CMD, RSV, ATYP, ADDR, PORT
		buff := make([]byte, 1024)
		n, err = localClient.Read(buff)
		if err != nil {
			log.Print(err)
			return
		}
		localReq := buff[:n]
		j := 0
		z := 0
		httpreq := []string{}
		for i := 0; i < n; i++ {
			if buff[i] == 32 {
				httpreq = append(httpreq, string(buff[j:i]))
				j = i + 1
			}
			if buff[i] == 10 {
				z += 1
			}
		}

		dstURI, err := url.ParseRequestURI(httpreq[1])
		if err != nil {
			log.Print(err)
			return
		}
		var dstAddr string
		var dstPort = "80"
		dstAddrPort := strings.Split(dstURI.Host, ":")
		if len(dstAddrPort) == 1 {
			dstAddr = dstAddrPort[0]
		} else if len(dstAddrPort) == 2 {
			dstAddr = dstAddrPort[0]
			dstPort = dstAddrPort[1]
		} else {
			log.Print("URL parse error!")
			return
		}

		resp = []byte{0x05, 0x01, 0x00, 0x03}
		// 域名
		// dstAddrLenBuff := bytes.NewBuffer(make([]byte, 1))
		// binary.BigEndian.PutUint16(dstAddrLenBuff, uint8(len(dstAddr)))
		// binary.Write(dstAddrLenBuff, binary.BigEndian, uint8(len(dstAddr)))
		// log.Print("AdrrLength:", dstAddrLenBuff.Bytes()[dstAddrLenBuff.Len()-1])
		// resp = append(resp, dstAddrLenBuff.Bytes()[dstAddrLenBuff.Len()-1])
		resp = append(resp, byte(len([]byte(dstAddr))))
		resp = append(resp, []byte(dstAddr)...)
		// 端口
		dstPortBuff := bytes.NewBuffer(make([]byte, 0))
		dstPortInt, err := strconv.ParseUint(dstPort, 10, 16)
		if err != nil {
			log.Fatal(err)
			return
		}
		binary.Write(dstPortBuff, binary.BigEndian, dstPortInt)
		dstPortBytes := dstPortBuff.Bytes() // int为8字节
		resp = append(resp, dstPortBytes[len(dstPortBytes)-2:]...)
		n, err = auth.EncodeWrite(dstServer, resp)
		if err != nil {
			log.Print(dstServer.RemoteAddr(), err)
			return
		}
		n, err = auth.DecodeRead(dstServer, resp)
		if err != nil {
			log.Print(dstServer.RemoteAddr(), err)
			return
		}
		var targetResp [10]byte
		copy(targetResp[:10], resp[:n])
		specialResp := [10]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		if targetResp != specialResp {
			log.Print("协议错误, 第二次协商返回出错")
			return
		}
		log.Print("认证成功")

		// 转发消息
		go func() {
			defer wg.Done()
			auth.Encrypt(localReq)
			dstServer.Write(localReq)
			// SecureCopy(localClient, dstServer, auth.Encrypt)
		}()

		go func() {
			defer wg.Done()
			SecureCopy(dstServer, localClient, auth.Decrypt)
		}()

		wg.Wait()

	} else {

		// 本地的内容copy到远程端
		go func() {
			defer wg.Done()
			SecureCopy(localClient, dstServer, auth.Encrypt)
		}()

		// 远程得到的内容copy到源地址
		go func() {
			defer wg.Done()
			SecureCopy(dstServer, localClient, auth.Decrypt)
		}()
		wg.Wait()
	}

}

func Client(listenAddrString string, serverAddrString string, encrytype string, passwd string, recvHTTPProto string) {
	//所有客户服务端的流都加密,
	auth, err := CreateAuth(encrytype, passwd)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("你的密码是: %s ,请保管好你的密码", passwd)

	// proxy地址
	serverAddr, err := net.ResolveTCPAddr("tcp", serverAddrString)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("连接远程服务器: %s ....", serverAddrString)

	listenAddr, err := net.ResolveTCPAddr("tcp", listenAddrString)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("监听本地端口: %s ", listenAddrString)

	listener, err := net.ListenTCP("tcp", listenAddr)
	if err != nil {
		log.Fatal(err)
	}

	for {
		localClient, err := listener.AcceptTCP()
		if err != nil {
			log.Fatal(err)
		}
		go handleProxyRequest(localClient, serverAddr, auth, recvHTTPProto)
	}
}
