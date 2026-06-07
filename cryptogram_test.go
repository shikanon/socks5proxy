package socks5proxy

import (
	"bytes"
	"errors"
	"github.com/stretchr/testify/assert"
	"log"
	"testing"
)

type bufferReadWriteCloser struct {
	*bytes.Buffer
}

func (b *bufferReadWriteCloser) Close() error {
	return nil
}

func TestSampleCipher(t *testing.T) {
	auth, err := CreateSimpleCipher("abc")
	if err != nil {
		log.Panic(err)
	}
	b := []byte{0x05, 0x01, 0x04}
	c := []byte{0x05, 0x01, 0x04}
	// 加密
	err = auth.Encrypt(b)
	if err != nil {
		log.Panic(err)
	}
	// 解密
	err = auth.Decrypt(b)
	if err != nil {
		log.Panic(err)
	}
	assert.Equal(t, b, c)
}

func TestRandomCipher(t *testing.T) {
	auth, err := CreateRandomCipher("123456")
	if err != nil {
		log.Panic(err)
	}
	var b []byte
	var c []byte
	for i := 0; i < 256; i++ {
		b = append(b, byte(i))
		c = append(c, byte(i))
	}
	// 加密
	err = auth.Encrypt(b)
	if err != nil {
		log.Panic(err)
	}
	// 解密
	err = auth.Decrypt(b)
	if err != nil {
		log.Panic(err)
	}
	assert.Equal(t, b, c)
}

func TestCipherDerivationUsesPasswordContent(t *testing.T) {
	simpleA, err := CreateSimpleCipher("aaaaaa")
	if err != nil {
		log.Panic(err)
	}
	simpleB, err := CreateSimpleCipher("bbbbbb")
	if err != nil {
		log.Panic(err)
	}
	randomA, err := CreateRandomCipher("aaaaaa")
	if err != nil {
		log.Panic(err)
	}
	randomB, err := CreateRandomCipher("bbbbbb")
	if err != nil {
		log.Panic(err)
	}

	assert.NotEqual(t, simpleA.Encode, simpleB.Encode)
	assert.NotEqual(t, randomA.Encode, randomB.Encode)
}

func TestSecureCopyOnlySecuresValidBytes(t *testing.T) {
	src := &bufferReadWriteCloser{Buffer: bytes.NewBufferString("abc")}
	dst := &bufferReadWriteCloser{Buffer: bytes.NewBuffer(nil)}
	var securedLen int

	written, err := SecureCopy(src, dst, func(b []byte) error {
		securedLen = len(b)
		for i := range b {
			b[i] = b[i] + 1
		}
		return nil
	})

	assert.NoError(t, err)
	assert.EqualValues(t, 3, written)
	assert.Equal(t, 3, securedLen)
	assert.Equal(t, "bcd", dst.String())
}

func TestSecureCopyReturnsSecureError(t *testing.T) {
	src := &bufferReadWriteCloser{Buffer: bytes.NewBufferString("abc")}
	dst := &bufferReadWriteCloser{Buffer: bytes.NewBuffer(nil)}
	expectedErr := errors.New("secure failed")

	written, err := SecureCopy(src, dst, func(b []byte) error {
		return expectedErr
	})

	assert.Equal(t, expectedErr, err)
	assert.Zero(t, written)
	assert.Equal(t, "", dst.String())
}
