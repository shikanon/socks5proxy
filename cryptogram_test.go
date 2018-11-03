package socks5proxy

import (
    "testing"
	"github.com/stretchr/testify/assert"
)


func TestSampleCipher(t *testing.T){
	auth, err := CreateSimpleCipher("abc")
	if err != nil{
		panic(err)
	}
	b := []byte{0x05,0x01,0x04}
	c := []byte{0x05,0x01,0x04}
	// 加密
	err = auth.Encrypt(b)
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

func TestRandomCipher(t *testing.T){
	auth,err := CreateRandomCipher("abc")
	if err != nil{
		panic(err)
	}
	b := []byte{0x05,0x01,0x04}
	c := []byte{0x05,0x01,0x04}
	// 加密
	err = auth.Encrypt(b)
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