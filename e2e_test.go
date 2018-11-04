package socks5proxy

import (
	"testing"
	"time"
	"github.com/stretchr/testify/assert"
	"sync"
	"log"
	"net"
)


func TestConncet(t *testing.T){
	go Server("127.0.0.1:18189", "random", "abcedfg")
	go Client("127.0.0.1:18190", "127.0.0.1:18189", "random", "abcedfg")

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
	go func(){
		defer wg.Done()
		n, err := conn.Read(readResult)
		if err != nil {
			log.Panic(err)
		}
		assert.Equal(t, readResult[0:n], []byte{0x05, 0x00})
	}()

	wg.Wait()
}
