package socks5proxy

import (
	"io"
	"net"
	"errors"
)

type socks5Auth struct {
	KeyMoved int // 移动位数
	Encode *[256]byte //编码表
	Decode *[256]byte //解码表
}

/**
加密方法：根据编码表将字符串进行编码 
**/
func (s *socks5Auth) Encrypt(b []byte) error{
    for i,v := range b {
		// 编码
		if int(v) >= len(s.Encode){
			return errors.New("socks5Auth Encode 超出范围")
		}
		b[i] = s.Encode[v]
	}
	return nil
}

func (s *socks5Auth) Decrypt(b []byte) error{
    for i,v := range b {
		// 编码
		if int(v) >= len(s.Encode){
			return errors.New("socks5Auth Encode 超出范围")
		}
		b[i] = s.Decode[v]
	}
	return nil
}

// 创建认证证书
func CreateAuth(passwd string) *socks5Auth{
	// 采用最简单的凯撒位移法
	sumint := 0
	for v := range passwd {
		sumint += int(v)
	}
	sumint = sumint % 256
	var encodeString [256]byte
	var decodeString [256]byte
	for i := 0; i < 256; i++{
		encodeString[i] = byte((i+sumint)%256)
		decodeString[i] = byte((i-sumint+256)%256)
	}
	return &socks5Auth{
		KeyMoved: sumint,
		Encode: &encodeString,
		Decode: &decodeString,
	}
}

// 加密安全连接，组合了net.conn接口和socks5Auth结构体
type SecureConn struct{
	net.Conn
    Auth *socks5Auth
}

func (c *SecureConn)EncodeWrite(b []byte) (int, error) {
	// 编码
	err := c.Auth.Encrypt(b)
	if err != nil{
		return 0, err
	}
	return c.Write(b)
}

func (c *SecureConn)DecodeRead(b []byte) (int, error) {
	// 解码
	n,err := c.Read(b)
	if err != nil{
		return 0, err
	}
	err = c.Auth.Decrypt(b)
	if err != nil{
		return 0, err
	}
	return n, err 
}

func SecureCopy(src io.ReadWriteCloser, dst io.ReadWriteCloser, secure func(b []byte) error) (written int64, err error) {
	size := 1024
	buf := make([]byte, size)
	for {
		nr, er := src.Read(buf)
		secure(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return written, err
}
