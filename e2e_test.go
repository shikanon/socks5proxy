package socks5proxy

import (
	"log"
	"net"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestConncet(t *testing.T) {
	go Server("127.0.0.1:18189", "random", "abcedfg")
	go Client("127.0.0.1:18190", "127.0.0.1:18189", "random", "abcedfg", "sock5")

	time.Sleep(1 * time.Second)

	// 连接
	conn, err := net.Dial("tcp", "127.0.0.1:18190")
	if err != nil {
		log.Fatalln(err)
	}
	defer conn.Close()

	readResult := make([]byte, 256)
	wg := new(sync.WaitGroup)
	wg.Add(2)

	// socks5协商验证
	// 写
	go func() {
		defer wg.Done()
		conn.Write([]byte{0x05, 0x01, 0x00})
	}()

	// 读
	go func() {
		defer wg.Done()
		n, err := conn.Read(readResult)
		if err != nil {
			log.Panic(err)
		}
		assert.Equal(t, readResult[0:n], []byte{0x05, 0x00})
	}()

	wg.Wait()
}

func TestHTTPConnect(t *testing.T) {
	go Server("127.0.0.1:18289", "random", "abcedfg1")
	go Client("127.0.0.1:18290", "127.0.0.1:18289", "random", "abcedfg1", "http")

	time.Sleep(1 * time.Second)

	ProxyURI, err := url.ParseRequestURI("http://127.0.0.1:18290")
	if err != nil {
		log.Panic(err)
	}
	reqClient := http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			Proxy:               http.ProxyURL(ProxyURI),
			TLSHandshakeTimeout: 1 * time.Second,
		},
	}
	// http.ListenAndServe

	req, err := http.NewRequest("GET", "http://www.baidu.com/", nil)
	if err != nil {
		log.Panic(err)
	}
	resp, err := reqClient.Do(req)
	if err != nil {
		log.Panic(err)
	}
	assert.Equal(t, resp.StatusCode, 200)
	var respbody []byte
	n, err := resp.Body.Read(respbody)
	if err != nil {
		log.Panic(err)
	}
	log.Print(string(respbody[:n]))
}
