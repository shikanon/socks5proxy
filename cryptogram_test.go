package socks5proxy

import (
    "testing"
	"github.com/stretchr/testify/assert"
	"log"
)


func TestSampleCipher(t *testing.T){
	auth, err := CreateSimpleCipher("abc")
	if err != nil{
		log.Panic(err)
	}
	b := []byte{0x05,0x01,0x04}
	c := []byte{0x05,0x01,0x04}
	// 加密
	err = auth.Encrypt(b)
	if err != nil{
		log.Panic(err)
	}
	// 解密
	err = auth.Decrypt(b)
	if err != nil{
		log.Panic(err)
	}
	assert.Equal(t, b, c)
}

func TestRandomCipher(t *testing.T){
	auth,err := CreateRandomCipher("123456")
	if err != nil{
		log.Panic(err)
	}
	var b []byte
	var c []byte
	for i:=0;i<256; i++{
		b = append(b, byte(i))
		c = append(c,byte(i))
	}
	// 加密
	err = auth.Encrypt(b)
	if err != nil{
		log.Panic(err)
	}
	// 解密
	err = auth.Decrypt(b)
	if err != nil{
		log.Panic(err)
	}
	assert.Equal(t, b, c)
}