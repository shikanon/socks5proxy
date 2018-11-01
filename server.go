package socks5proxy

import (
    "net"
    "log"
    "sync"
)


func handleClientRequest(client *SecureConn){
	if client == nil {
        return
    }
    defer client.Close()
    
    // 初始化一个字符串buff
    buff := make([]byte, 255)

    // 认证协商
    var proto ProtocolVersion
    n, err := client.DecodeRead(buff)
    resp, err := proto.HandleHandshake(buff[0:n])
    client.EncodeWrite(resp)
	if err != nil {
        log.Print(client.RemoteAddr(), err)
		return
    }

	//获取客户端代理的请求
    var request Socks5Resolution
    n, err = client.DecodeRead(buff)
    resp, err = request.LSTRequest(buff[0:n])
    client.EncodeWrite(resp)
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
        SecureCopy(client, dstServer, client.Auth.Decrypt)
    }()
    
    // 远程得到的内容copy到源地址
    go func() {
        defer wg.Done()
        SecureCopy(dstServer, client, client.Auth.Encrypt)
    }()
    wg.Wait()

}

func Server(listenAddrString string, passwd string) {
    //所有客户服务端的流都加密,
    auth := CreateAuth(passwd)
    log.Printf("你的密码是:%s ,请保管好你的密码", passwd)

    // 监听客户端
    listener,err := net.Listen("tcp", listenAddrString)
    if err != nil {
        log.Fatal(err)
    }
    for  {
        conn,err := listener.Accept()
        if err != nil {
            log.Fatal(err)
        }
        go handleClientRequest(
            &SecureConn{
                Conn: conn,
                Auth: auth,
            })
    }
}