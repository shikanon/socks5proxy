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

type chunkedReadWriter struct {
	chunks [][]byte
	write  bytes.Buffer
}

func (c *chunkedReadWriter) Read(p []byte) (int, error) {
	if len(c.chunks) == 0 {
		return 0, io.EOF
	}
	chunk := c.chunks[0]
	c.chunks = c.chunks[1:]
	n := copy(p, chunk)
	return n, nil
}

func (c *chunkedReadWriter) Write(p []byte) (int, error) {
	return c.write.Write(p)
}

type failingReadWriter struct {
	err error
}

func (f *failingReadWriter) Read([]byte) (int, error) {
	return 0, f.err
}

func (f *failingReadWriter) Write(p []byte) (int, error) {
	return len(p), nil
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
	return rw.Write(b)
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

func TestHandleRequestReturnsReadError(t *testing.T) {
	expectedErr := errors.New("read failed")
	client := &failingReadWriter{err: expectedErr}
	auth := stubAuth{}

	err := handleRequest(client, auth, &Socks5Resolution{})

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

func TestHandleRequestHandlesFragmentedDomainRequest(t *testing.T) {
	requestBytes := []byte{
		0x05, 0x01, 0x00, 0x03,
		0x09,
		'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't',
		0x00, 0x50,
	}
	client := &chunkedReadWriter{
		chunks: [][]byte{
			requestBytes[:2],
			requestBytes[2:4],
			requestBytes[4:5],
			requestBytes[5:8],
			requestBytes[8:12],
			requestBytes[12:],
		},
	}
	auth := stubAuth{}
	request := &Socks5Resolution{}

	err := handleRequest(client, auth, request)

	assert.NoError(t, err)
	assert.Equal(t, "localhost", request.DSTDOMAIN)
	assert.Equal(t, uint16(80), request.DSTPORT)
	assert.Equal(t, []byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, client.write.Bytes())
}

func TestLSTRequestRejectsUnexpectedDomainLength(t *testing.T) {
	request := &Socks5Resolution{}
	packet := []byte{
		0x05, 0x01, 0x00, 0x03,
		0x03,
		'a', 'b', 'c',
		0x00, 0x50,
		'z', 'z',
	}

	_, err := request.LSTRequest(packet)

	assert.EqualError(t, err, "请求协议长度错误")
}
