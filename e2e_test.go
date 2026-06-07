package socks5proxy

import (
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestConncet(t *testing.T) {
	go Server("127.0.0.1:18189", "random", "abcedfg")
	go Client("127.0.0.1:18190", "127.0.0.1:18189", "random", "abcedfg", "socks5")

	time.Sleep(1 * time.Second)

	// 连接
	conn, err := net.Dial("tcp", "127.0.0.1:18190")
	if err != nil {
		t.Fatal(err)
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

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()

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

	req, err := http.NewRequest("GET", target.URL, nil)
	if err != nil {
		log.Panic(err)
	}
	resp, err := reqClient.Do(req)
	if err != nil {
		log.Panic(err)
	}
	assert.Equal(t, resp.StatusCode, 200)
	defer resp.Body.Close()
	respbody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Panic(err)
	}
	log.Print(string(respbody))
}
