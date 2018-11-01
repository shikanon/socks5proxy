package socks5proxy

import (
    "testing"
	"github.com/stretchr/testify/assert"
	// "log"
)

func TestCreateAuth(t *testing.T){
	auth := CreateAuth("abc")
	assert.Equal(t, int(auth.Encode[0]), auth.KeyMoved)
}

func TestSocks5Auth(t *testing.T){
	auth := CreateAuth("abc")
	b := []byte{0x05,0x01,0x04}
	c := []byte{0x05,0x01,0x04}
	// 加密
	err := auth.Encrypt(b)
	if err != nil{
		panic(err)
	}
	// 解密
	err = auth.Decrypt(b)
	if err != nil{
		panic(err)
	}
	assert.Equal(t, b, c)
}