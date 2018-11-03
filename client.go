package socks5proxy

import (
    "net"
    "log"
)

type TcpClient struct{
	conn *net.TCPConn
	server *net.TCPAddr
}

func handleProxyRequest(localClient *net.TCPConn,serverAddr *net.TCPAddr, auth socks5Auth){

    // 远程连接IO
    dstServer, err := net.DialTCP("tcp", nil, serverAddr)
    defer dstServer.Close()
    if err != nil {
        log.Print(err)
        return 
    }
    defer dstServer.Close()

    defer localClient.Close()

    go SecureCopy(localClient, dstServer, auth.Encrypt)
    SecureCopy(dstServer, localClient, auth.Decrypt)
}

func Client(listenAddrString string, serverAddrString string, encrytype string, passwd string){
    //所有客户服务端的流都加密,
    auth,err := CreateAuth(encrytype, passwd)
    if err != nil {
		log.Fatal(err)
    }
    log.Printf("你的密码是:%s ,请保管好你的密码", passwd)

    // proxy地址
    serverAddr, err := net.ResolveTCPAddr("tcp", serverAddrString)
	if err != nil {
		log.Fatal(err)
    }

    listenAddr, err := net.ResolveTCPAddr("tcp", listenAddrString)
	if err != nil {
		log.Fatal(err)
	}
	
    listener, err := net.ListenTCP("tcp", listenAddr)
    if err != nil {
        log.Fatal(err)
	}

    for  {
        localClient, err := listener.AcceptTCP()
        if err != nil {
            log.Fatal(err)
        }
        go handleProxyRequest(localClient, serverAddr, auth)
    }
}