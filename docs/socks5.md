# SOCKS5协议介绍

SOCKS是一种网络传输协议，主要用于客户端与外网服务器之间通讯的中间传递，SOCKS是"SOCKetS"的缩写。
SOCKS5是SOCKS4的升级版，其主要多了鉴定、IPv6、UDP支持。

SOCKS5协议可以分为三个部分：
* (1) 协议版本及认证方式
* (2) 根据认证方式执行对应的认证
* (3) 请求信息
  
<!-- TOC -->

- [SOCKS5协议介绍](#socks5协议介绍)
            - [（1）协议版本及认证方式](#1协议版本及认证方式)
            - [（2）根据认证方式执行对应的认证](#2根据认证方式执行对应的认证)
            - [（3）请求信息](#3请求信息)
            - [（4）最后将信息进行转发即可](#4最后将信息进行转发即可)

<!-- /TOC -->

#### （1）协议版本及认证方式
创建与SOCKS5服务器的TCP连接后**客户端**需要先发送请求来协议版本及认证方式，


|VER|	NMETHODS |	METHODS |
|----|-----|-------|
|1	|1	|1-255  |

* VER是SOCKS版本，这里应该是0x05；
* NMETHODS是METHODS部分的长度；
* METHODS是客户端支持的认证方式列表，每个方法占1字节。当前的定义是：
    * 0x00 不需要认证
    * 0x01 GSSAPI
    * 0x02 用户名、密码认证
    * 0x03 - 0x7F由IANA分配（保留）
    * 0x80 - 0xFE为私人方法保留
    * 0xFF 无可接受的方法
  

**服务器**回复客户端可用方法：

|VER|	METHOD |
|----|-----|
|1	|1  |

* VER是SOCKS版本，这里应该是0x05；
* METHOD是服务端选中的方法。如果返回0xFF表示没有一个认证方法被选中，客户端需要关闭连接。

代码实现：

```
type ProtocolVersion struct {
    VER uint8
    NMETHODS uint8
    METHODS []uint8
}


func (s *ProtocolVersion) handshake(conn net.Conn) error {
    b := make([]byte, 255)
    n, err := conn.Read(b)
    if err != nil {
        log.Println(err)
        return err
    }
    s.VER = b[0] //ReadByte reads and returns a single byte，第一个参数为socks的版本号
    s.NMETHODS = b[1] //nmethods是记录methods的长度的。nmethods的长度是1个字节
    if n != int(2+s.NMETHODS) {
        return errors.New("协议错误, sNMETHODS不对")
    }
    s.METHODS = b[2:2+s.NMETHODS] //读取指定长度信息，读取正好len(buf)长度的字节。如果字节数不是指定长度，则返回错误信息和正确的字节数

    if s.VER != 5 {
        return errors.New("该协议不是socks5协议")
    }

    //服务器回应客户端消息:
    //第一个参数表示版本号为5，即socks5协议，
    // 第二个参数表示服务端选中的认证方法，0即无需密码访问, 2表示需要用户名和密码进行验证。  
    resp :=[]byte{5, 0} 
    conn.Write(resp)
    return nil
} 
```


#### （2）根据认证方式执行对应的认证

SOCKS5协议提供5种认证方式：
* 0x00 不需要认证
* 0x01 GSSAPI
* 0x02 用户名、密码认证
* 0x03 - 0x7F由IANA分配（保留）
* 0x80 - 0xFE为私人方法保留
  
这里就主要介绍用户名、密码认证。
在客户端、服务端协商使用用户名密码认证后，客户端发出用户名密码：

|鉴定协议版本	|用户名长度	|用户名	|密码长度	|密码   |
|------|----|------|---------|---|
|1	|1	|动态	|1	|动态   |

服务器鉴定后发出如下回应：

|鉴定协议版本	|鉴定状态 |
|------|--------|
|1	|1  |

其中鉴定状态 0x00 表示成功，0x01 表示失败。

代码实现：
```
type Socks5Auth struct {
    VER uint8
    ULEN uint8
    UNAME string
    PLEN uint8
    PASSWD string
}

func (s *Socks5Auth) authenticate(conn net.Conn) error {
    b := make([]byte, 128)
    n, err := conn.Read(b)
    if err != nil{
        log.Println(err)
        return err
    }

    s.VER = b[0]
    if s.VER != 5 {
        return errors.New("该协议不是socks5协议")
    }

    s.ULEN = b[1]
    s.UNAME = string(b[2:2+s.ULEN])
    s.PLEN = b[2+s.ULEN+1]
    s.PASSWD = string(b[n-int(s.PLEN):n])
    log.Println(s.UNAME, s.PASSWD)
    if username != s.UNAME || passwd != s.PASSWD {
        return errors.New("账号密码错误")
    }

    /**
    回应客户端,响应客户端连接成功
    The server verifies the supplied UNAME and PASSWD, and sends the
    following response:
                            +----+--------+
                            |VER | STATUS |
                            +----+--------+
                            | 1  |   1    |
                            +----+--------+
    A STATUS field of X'00' indicates success. If the server returns a
    `failure' (STATUS value other than X'00') status, it MUST close the
    connection.
    */
	resp := []byte{0x05, 0x00}
    conn.Write(resp) 

    return nil
}
```

但其实，现在大家都习惯自己采用加密流的方式进行加密，很少采用用户名密码的形式进行加密，后面章节会介绍一种对SOCKS的混淆加密方式。


#### （3）请求信息
认证结束后客户端就可以发送请求信息。如果认证方法有特殊封装要求，请求必须按照方法所定义的方式进行封装解密，其原始格式如下：

|VER	|CMD	|RSV	|ATYP	|DST.ADDR	|DST.PORT|
|------|-------|-------|-------|---------|-----------|
|1	|1	|0x00	|1	|动态	|2 |

* VER是SOCKS版本，这里应该是0x05；
* CMD是SOCK的命令码
    * 0x01表示CONNECT请求
    * 0x02表示BIND请求
    * 0x03表示UDP转发
* RSV 0x00，保留
* ATYP DST.ADDR类型
* DST.ADDR 目的地址
    * 0x01 IPv4地址，DST.ADDR部分4字节长度
    * 0x03 域名，DST.ADDR部分第一个字节为域名长度，DST.ADDR剩余的内容为域名，没有\0结尾。
    * 0x04 IPv6地址，16个字节长度。
* DST.PORT 网络字节序表示的目的端口

代码实现：
```
type Socks5Resolution struct {
    VER uint8
    CMD uint8
    RSV uint8
    ATYP uint8
    DSTADDR []byte
    DSTPORT uint16
    DSTDOMAIN string
    RAWADDR *net.TCPAddr
}

func (s *Socks5Resolution) lstRequest(conn net.Conn) error {
    b := make([]byte, 128)
    n, err := conn.Read(b)
    if err != nil || n < 7 {
        log.Println(err)
        return errors.New("请求协议错误")
    }
    s.VER = b[0]
    if s.VER != 5 {
        return errors.New("该协议不是socks5协议")
    }

    s.CMD = b[1]
    if s.CMD != 1 { 
        return errors.New("客户端请求类型不为代理连接, 其他功能暂时不支持.")
    }
    s.RSV = b[2] //RSV保留字端，值长度为1个字节

    s.ATYP = b[3]

    switch s.ATYP {
    case 1:
        //	IP V4 address: X'01'
        s.DSTADDR = b[4 : 4+net.IPv4len]
    case 3:
        //	DOMAINNAME: X'03'
        s.DSTDOMAIN = string(b[5:n-2])
        ipAddr, err := net.ResolveIPAddr("ip", s.DSTDOMAIN)
		if err != nil {
			return err
		}
        s.DSTADDR = ipAddr.IP
    case 4:
        //	IP V6 address: X'04'
        s.DSTADDR = b[4 : 4+net.IPv6len]
	default:
		return errors.New("IP地址错误")
    }

    s.DSTPORT = binary.BigEndian.Uint16(b[n-2:n])
    // DSTADDR全部换成IP地址，可以防止DNS污染和封杀
    s.RAWADDR = &net.TCPAddr{
		IP:   s.DSTADDR,
		Port: int(s.DSTPORT),
    }
    
    /**
    回应客户端,响应客户端连接成功
        +----+-----+-------+------+----------+----------+
        |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+
    */
	resp := []byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
    conn.Write(resp) 

    return nil


}
```


#### （4）最后将信息进行转发即可

代码实现:
```
    wg := new(sync.WaitGroup)
    wg.Add(2)

    go func() {
		defer wg.Done()
		defer dstServer.Close()
        io.Copy(dstServer, client)
    }()

    go func() {
		defer wg.Done()
        defer client.Close()
        io.Copy(client, dstServer)
    }()

    wg.Wait()
```