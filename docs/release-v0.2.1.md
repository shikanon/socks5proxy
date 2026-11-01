# v0.2.1

提供 macOS Apple Silicon 可运行客户端 `socks5proxy_client_darwin_arm64`，以及 Linux/Windows amd64、arm64 客户端与服务端。下载同版本 `SHA256SUMS` 校验，添加执行权限后用 `-version` 确认版本。

本版本包含 v0.2.0 的全局 IPv4 TUN、网站通配符分流、PAC 和每日令牌表，并修复移动构建临时源码遗漏 `routing` 包的问题。

## 使用

指定网站走远程，其余直连：

```bash
chmod +x socks5proxy_client_darwin_arm64
./socks5proxy_client_darwin_arm64 \
  -mode proxy -server SERVER_IP:18888 -type random -passwd demo-only \
  -recv http -proxy-scope rules \
  -proxy-domains 'example.com,*.example.org' \
  -pac-listen 127.0.0.1:8090
```

浏览器 HTTP/HTTPS 代理设为 `127.0.0.1:8888`，或自动代理配置 URL 设为 `http://127.0.0.1:8090/proxy.pac`。也可用 `-rules-file` 加载规则。命中规则的连接在远程失败时返回错误，不主动回落直连；`*.example.org` 包含根域名和多级子域名。

全局 IPv4（需预先配置匹配的 TLS TCP 服务端、令牌和 CA）：

```bash
sudo ./socks5proxy_client_darwin_arm64 \
  -mode tunnel -transport tcp \
  -server SERVER_IP:1443 -server-name vpn.example.com \
  -client-id desktop -token-file ./desktop.token -ca ./server.crt
```

无需 TLS 的学习模式使用 `-transport tcp-table -table-file ./token-table.json`，该表先由服务端生成并复制至客户端。

## 验证与文档

网址分流实现已完成本地 race/vet/staticcheck、十种桌面二进制构建、Apple Silicon 原生 HTTP/CONNECT/SOCKS5/PAC 实测；Linux 低 FD 400 次连接回收和三种全局 TUN 集成测试均通过，见[验证记录](https://github.com/shikanon/socks5proxy/blob/v0.2.1/docs/proxy-scopes-verification-2026-11-01.md)。

- [全局代理、指定网站与通配符](https://github.com/shikanon/socks5proxy/blob/v0.2.1/docs/proxy-scopes.md)
- [隧道部署](https://github.com/shikanon/socks5proxy/blob/v0.2.1/docs/tunnel.md)
- [每日令牌表](https://github.com/shikanon/socks5proxy/blob/v0.2.1/docs/token-table.md)
- [数据映射](https://github.com/shikanon/socks5proxy/blob/v0.2.1/docs/data-mapping.md)

HTTPS 规则按主机名匹配，不能识别加密路径。全局 TUN 不承载 IPv6；macOS/Windows 有 IPv6 阻断策略，Linux 需自行限制 IPv6。更具体的局域网/主机路由优先；移动端仍只提供全局 IPv4。令牌表和 proxy 字节混淆不是现代安全加密。
