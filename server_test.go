package socks5proxy

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

type stubAuth struct {
	decodeReadFunc  func(io.ReadWriter, []byte) (int, error)
	encodeWriteFunc func(io.ReadWriter, []byte) (int, error)
}

func (s stubAuth) Encrypt([]byte) error {
	return nil
}

func (s stubAuth) Decrypt([]byte) error {
	return nil
}

func (s stubAuth) EncodeWrite(rw io.ReadWriter, b []byte) (int, error) {
	if s.encodeWriteFunc != nil {
		return s.encodeWriteFunc(rw, b)
	}
	return len(b), nil
}

func (s stubAuth) DecodeRead(rw io.ReadWriter, b []byte) (int, error) {
	if s.decodeReadFunc != nil {
		return s.decodeReadFunc(rw, b)
	}
	return 0, nil
}

func TestHandleHandshakeReturnsDecodeReadError(t *testing.T) {
	expectedErr := errors.New("decode read failed")
	auth := stubAuth{
		decodeReadFunc: func(io.ReadWriter, []byte) (int, error) {
			return 0, expectedErr
		},
	}

	err := handleHandshake(bytes.NewBuffer(nil), auth, make([]byte, 255), &ProtocolVersion{})

	assert.Equal(t, expectedErr, err)
}

func TestHandleRequestReturnsDecodeReadError(t *testing.T) {
	expectedErr := errors.New("decode read failed")
	auth := stubAuth{
		decodeReadFunc: func(io.ReadWriter, []byte) (int, error) {
			return 0, expectedErr
		},
	}

	err := handleRequest(bytes.NewBuffer(nil), auth, make([]byte, 255), &Socks5Resolution{})

	assert.Equal(t, expectedErr, err)
}

func TestHandleHandshakeReturnsEncodeWriteError(t *testing.T) {
	expectedErr := errors.New("encode write failed")
	auth := stubAuth{
		decodeReadFunc: func(_ io.ReadWriter, b []byte) (int, error) {
			handshake := []byte{0x05, 0x01, 0x00}
			copy(b, handshake)
			return len(handshake), nil
		},
		encodeWriteFunc: func(io.ReadWriter, []byte) (int, error) {
			return 0, expectedErr
		},
	}

	err := handleHandshake(bytes.NewBuffer(nil), auth, make([]byte, 255), &ProtocolVersion{})

	assert.Equal(t, expectedErr, err)
}
