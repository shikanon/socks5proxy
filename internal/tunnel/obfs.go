package tunnel

import (
	"github.com/shikanon/socks5proxy"
	"github.com/shikanon/socks5proxy/internal/tunnel/protocol"
)

func NewObfuscator(mode, key string) (protocol.Cipher, error) {
	normalized, err := NormalizeObfs(mode)
	if err != nil {
		return nil, err
	}
	if normalized == "none" {
		return nil, nil
	}
	return socks5proxy.CreateAuth(normalized, key)
}
