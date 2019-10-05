package socks5proxy

import (
    "net"
    "log"
    "errors"
    "encoding/binary"
)

const (
    SOCKS_VERSION = 0x05
    METHOD_CODE = 0x00
)

/**
    The localConn connects to the dstServer, and sends a ver
    identifier/method selection message:
                +----+----------+----------+
                |VER | NMETHODS | METHODS  |
                +----+----------+----------+
                | 1  |    1     | 1 to 255 |
                +----+----------+----------+
    The VER field is set to X'05' for this ver of the protocol.  The
    NMETHODS field contains the number of method identifier octets that
    appear in the METHODS field.
    METHODS常见的几种方式如下:
    1>.数字“0”：表示不需要用户名或者密码验证；
    2>.数字“1”：GSSAPI是SSH支持的一种验证方式；
    3>.数字“2”：表示需要用户名和密码进行验证；
    4>.数字“3”至“7F”：表示用于IANA 分配(IANA ASSIGNED)
    5>.数字“80”至“FE”表示私人方法保留(RESERVED FOR PRIVATE METHODS)
    4>.数字“FF”：不支持所有的验证方式，无法进行连接
**/
type ProtocolVersion struct {
    VER uint8
    NMETHODS uint8
    METHODS []uint8
}


func (s *ProtocolVersion) HandleHandshake(b []byte) ([]byte, error) {
    n := len(b)
    if n < 3{
        return nil, errors.New("协议错误, sNMETHODS不对")
    }
    s.VER = b[0] //ReadByte reads and returns a single byte，第一个参数为socks的版本号
    if s.VER != 0x05 {
        return nil, errors.New("协议错误, version版本不为5!")
    }
    s.NMETHODS = b[1] //nmethods是记录methods的长度的。nmethods的长度是1个字节
    if n != int(2+s.NMETHODS) {
        return nil, errors.New("协议错误, sNMETHODS不对")
    }
    s.METHODS = b[2:2+s.NMETHODS] //读取指定长度信息，读取正好len(buf)长度的字节。如果字节数不是指定长度，则返回错误信息和正确的字节数
    
    useMethod := byte(0x00) //默认不需要密码
    for _,v := range s.METHODS {
        if v == METHOD_CODE {
            useMethod = METHOD_CODE
        }
    }

    if s.VER != SOCKS_VERSION {
        return  nil, errors.New("该协议不是socks5协议")
    }

	//服务器回应客户端消息:
    //第一个参数表示版本号为5，即socks5协议，
	// 第二个参数表示服务端选中的认证方法，0即无需密码访问, 2表示需要用户名和密码进行验证。
    // 88是一种私有的加密协议
    if useMethod != METHOD_CODE{
        return  nil, errors.New("协议错误, 加密方法不对")
    }
    resp :=[]byte{SOCKS_VERSION, useMethod}
	return resp, nil
	
}

func (s *ProtocolVersion) SentHandshake(conn net.Conn) error {
	// 采用0x88私有加密方法进行加密
	resp := []byte{SOCKS_VERSION, 0x01, METHOD_CODE}
	conn.Write(resp)
	return nil
}




/*
    This begins with the client producing a
    Username/Password request:
    +----+------+----------+------+----------+
    |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
    +----+------+----------+------+----------+
    | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
    +----+------+----------+------+----------+

*/


type Socks5AuthUPasswd struct {
    VER uint8
    ULEN uint8
    UNAME string
    PLEN uint8
    PASSWD string
}

func (s *Socks5AuthUPasswd) HandleAuth(b []byte) ([]byte, error) {
    // b := make([]byte, 128)
    // n, err := conn.Read(b)
    // if err != nil{
    //     log.Println(err)
    //     return err
    // }
    n := len(b)

    s.VER = b[0]
    if s.VER != 5 {
        return nil, errors.New("该协议不是socks5协议")
    }

    s.ULEN = b[1]
    s.UNAME = string(b[2:2+s.ULEN])
    s.PLEN = b[2+s.ULEN+1]
    s.PASSWD = string(b[n-int(s.PLEN):n])
    log.Println(s.UNAME, s.PASSWD)

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
	resp := []byte{SOCKS_VERSION, 0x00}
    // conn.Write(resp) 

    return resp, nil
}


/**
    结构：
    +----+-----+-------+------+----------+----------+
    |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    +----+-----+-------+------+----------+----------+
    | 1  |  1  | X'00' |  1   | Variable |    2     |
    +----+-----+-------+------+----------+----------+
    cmd代表客户端请求的类型，值长度也是1个字节，有三种类型：
        1>.数字“1”：表示客户端需要你帮忙代理连接，即CONNECT ；
        2>.数字“2”：表示让你代理服务器，帮他建立端口，即BIND ；
        3>.数字“3”：表示UDP连接请求用来建立一个在UDP延迟过程中操作UDP数据报的连接，即UDP ASSOCIATE；
    ATYP代表请求的远程服务器地址类型，它是一个可变参数，但是它值的长度1个字节，
    有三种类型：
        1>.数字“1”：表示是一个IPV4地址（IP V4 address）；
        2>.数字“3”：表示是一个域名（DOMAINNAME）；
        3>.数字“4”：表示是一个IPV6地址（IP V6 address）；

**/
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

func (s *Socks5Resolution) LSTRequest(b []byte) ([]byte, error) {
    // b := make([]byte, 128)
    // n, err := conn.Read(b)
    n := len(b)
    if n < 7 {
        return nil, errors.New("请求协议错误")
    }
    s.VER = b[0]
    if s.VER != SOCKS_VERSION {
        return nil, errors.New("该协议不是socks5协议")
    }

    s.CMD = b[1]
    if s.CMD != 1 { 
        return nil, errors.New("客户端请求类型不为代理连接, 其他功能暂时不支持.")
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
			return nil, err
		}
        s.DSTADDR = ipAddr.IP
    case 4:
        //	IP V6 address: X'04'
        s.DSTADDR = b[4 : 4+net.IPv6len]
	default:
		return nil, errors.New("IP地址错误")
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
	resp := []byte{SOCKS_VERSION, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
    // conn.Write(resp) 

    return resp, nil
}
