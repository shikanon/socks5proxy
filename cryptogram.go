package socks5proxy

import (
	"errors"
	"io"
)

const (
	RANDOM_A = 13
	RANDOM_B = 7
	RANDOM_M = 256
)

type socks5Auth interface {
	Encrypt([]byte) error
	Decrypt([]byte) error
	EncodeWrite(io.ReadWriter, []byte) (int, error)
	DecodeRead(io.ReadWriter, []byte) (int, error)
}

type DefaultAuth struct {
	Encode *[256]byte //编码表
	Decode *[256]byte //解码表
}

// 这些变换仅用于流量混淆，不提供现代密码学意义上的机密性或完整性。

func (s *DefaultAuth) Encrypt(b []byte) error {
	for i, v := range b {
		// 编码
		if int(v) >= len(s.Encode) {
			return errors.New("socks5Auth Encode 超出范围")
		}
		b[i] = s.Encode[v]
	}
	return nil
}

func (s *DefaultAuth) Decrypt(b []byte) error {
	for i, v := range b {
		// 编码
		if int(v) >= len(s.Encode) {
			return errors.New("socks5Auth Encode 超出范围")
		}
		b[i] = s.Decode[v]
	}
	return nil
}

func (s *DefaultAuth) EncodeWrite(c io.ReadWriter, b []byte) (int, error) {
	// 编码
	err := s.Encrypt(b)
	if err != nil {
		return 0, err
	}
	return c.Write(b)
}

func (s *DefaultAuth) DecodeRead(c io.ReadWriter, b []byte) (int, error) {
	// 解码
	n, err := c.Read(b)
	if err != nil {
		return 0, err
	}
	err = s.Decrypt(b)
	if err != nil {
		return 0, err
	}
	return n, err
}

func CreateSimpleCipher(passwd string) (*DefaultAuth, error) {
	var s *DefaultAuth
	// 使用简单的凯撒位移做流量混淆。
	sumint := 0
	if len(passwd) == 0 {
		return nil, errors.New("密码不能为空")
	}
	for _, v := range []byte(passwd) {
		sumint += int(v)
	}
	sumint = sumint % 256
	var encodeString [256]byte
	var decodeString [256]byte
	for i := 0; i < 256; i++ {
		encodeString[i] = byte((i + sumint) % 256)
		decodeString[i] = byte((i - sumint + 256) % 256)
	}
	s = &DefaultAuth{
		Encode: &encodeString,
		Decode: &decodeString,
	}
	return s, nil
}

func CreateRandomCipher(passwd string) (*DefaultAuth, error) {
	var s *DefaultAuth
	// 使用线性同余生成的替换表做流量混淆。
	sumint := 0
	if len(passwd) == 0 {
		return nil, errors.New("密码不能为空")
	}
	for _, v := range []byte(passwd) {
		sumint += int(v)
	}
	var encodeString [256]byte
	var decodeString [256]byte
	// 创建随机数 (a*x + b) mod m
	for i := 0; i < 256; i++ {
		encodeString[i] = byte((RANDOM_A*sumint + RANDOM_B) % RANDOM_M)
		decodeString[(RANDOM_A*sumint+RANDOM_B)%RANDOM_M] = byte(i)
		sumint = (RANDOM_A*sumint + RANDOM_B) % RANDOM_M
	}
	s = &DefaultAuth{
		Encode: &encodeString,
		Decode: &decodeString,
	}
	return s, nil
}

// 创建流量混淆器。当前实现不是安全通道。
func CreateAuth(encrytype string, passwd string) (socks5Auth, error) {
	if len(passwd) == 0 {
		return nil, errors.New("密码不能为空")
	}
	var s socks5Auth
	var err error
	switch encrytype {
	case "simple":
		s, err = CreateSimpleCipher(passwd)

	case "random":
		s, err = CreateRandomCipher(passwd)
	default:
		return nil, errors.New("错误混淆类型！")
	}

	if err != nil {
		return nil, err
	}
	return s, nil
}

// SecureCopy 对有效负载做流量混淆后再转发。
func SecureCopy(src io.ReadWriteCloser, dst io.ReadWriteCloser, secure func(b []byte) error) (written int64, err error) {
	size := 1024
	buf := make([]byte, size)
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			if secureErr := secure(buf[:nr]); secureErr != nil {
				err = secureErr
				break
			}
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
