package socks5proxy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
)

func handleProxyRequest(localClient *net.TCPConn, serverAddr *net.TCPAddr, auth socks5Auth, recvHTTPProto string) error {

	// 远程连接IO
	dstServer, err := net.DialTCP("tcp", nil, serverAddr)
	if err != nil {
		return err
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
			return err
		}
		if n == 0 {
			return errors.New("协议错误,服务器返回为空")
		}
		if resp[1] == 0x00 && n == 2 {
			log.Print("success")
		} else {
			return errors.New("协议错误，连接失败")
		}
		// 第二阶段根据认证方式执行对应的认证，由于采用无密码格式，这里省略验证
		// 第三阶段请求信息
		// VER, CMD, RSV, ATYP, ADDR, PORT
		buff := make([]byte, 1024)
		n, err = localClient.Read(buff)
		if err != nil {
			return err
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
			return err
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
			return errors.New("URL parse error")
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
			return err
		}
		binary.Write(dstPortBuff, binary.BigEndian, dstPortInt)
		dstPortBytes := dstPortBuff.Bytes() // int为8字节
		resp = append(resp, dstPortBytes[len(dstPortBytes)-2:]...)
		_, err = auth.EncodeWrite(dstServer, resp)
		if err != nil {
			return err
		}
		n, err = auth.DecodeRead(dstServer, resp)
		if err != nil {
			return err
		}
		var targetResp [10]byte
		copy(targetResp[:10], resp[:n])
		specialResp := [10]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		if targetResp != specialResp {
			return errors.New("协议错误, 第二次协商返回出错")
		}
		log.Print("认证成功")

		// 转发消息
		go func() {
			defer wg.Done()
			if err := auth.Encrypt(localReq); err != nil {
				log.Print(err)
				return
			}
			if _, err := dstServer.Write(localReq); err != nil {
				log.Print(err)
			}
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

	return nil
}

func Client(listenAddrString string, serverAddrString string, encrytype string, passwd string, recvHTTPProto string) error {
	//所有客户服务端的流都加密,
	auth, err := CreateAuth(encrytype, passwd)
	if err != nil {
		return err
	}

	// proxy地址
	serverAddr, err := net.ResolveTCPAddr("tcp", serverAddrString)
	if err != nil {
		return err
	}
	log.Printf("连接远程服务器: %s ....", serverAddrString)

	listenAddr, err := net.ResolveTCPAddr("tcp", listenAddrString)
	if err != nil {
		return err
	}
	log.Printf("监听本地端口: %s ", listenAddrString)

	listener, err := net.ListenTCP("tcp", listenAddr)
	if err != nil {
		return err
	}

	for {
		localClient, err := listener.AcceptTCP()
		if err != nil {
			log.Print(err)
			continue
		}
		go func(clientConn *net.TCPConn) {
			if err := handleProxyRequest(clientConn, serverAddr, auth, recvHTTPProto); err != nil {
				log.Print(err)
			}
		}(localClient)
	}
}
