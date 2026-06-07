package socks5proxy

import "testing"

func TestClientReturnsErrorOnInvalidServerAddress(t *testing.T) {
	if err := Client("127.0.0.1:0", "bad-addr", "random", "passwd", "http"); err == nil {
		t.Fatal("expected client startup error")
	}
}

func TestServerReturnsErrorOnInvalidListenAddress(t *testing.T) {
	if err := Server("bad-addr", "random", "passwd"); err == nil {
		t.Fatal("expected server startup error")
	}
}
