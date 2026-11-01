# v0.2.0

macOS Apple Silicon 客户端：`socks5proxy_client_darwin_arm64`。下载同版本 `SHA256SUMS` 校验，添加执行权限后用 `-version` 确认版本。

## 功能

- 桌面 HTTP/SOCKS5 客户端新增 `-proxy-scope all|rules`。`rules` 根据目标主机选择远程或直连，支持 `*`、`?`、根域名及多级子域名。
- `-proxy-domains` 与 `-rules-file` 可以合并使用；`-pac-listen` 提供同规则的 `/proxy.pac`。命中规则的连接在代理失败时返回错误。
- 系统全局流量使用原有 `-mode tunnel`，支持 IPv4 TCP、UDP、ICMP 和 DNS；网站分流参数仅适用于应用代理。
- 新增学习用 `-transport tcp-table`：无需 TLS，由服务端生成并保存 8–16 位随机令牌表，与 UTC 当日时间戳派生字节映射。不是现代安全加密，需两端共享表。
- 桌面客户端和服务端均支持 `-version`；发布脚本支持 `VERSION` 与 `OUTPUT_DIR`。

## 使用

网址分流：

```bash
./socks5proxy_client_darwin_arm64 \
  -mode proxy -server SERVER_IP:18888 -type random -passwd demo-only \
  -recv http -proxy-scope rules \
  -proxy-domains 'example.com,*.example.org' \
  -pac-listen 127.0.0.1:8090
```

浏览器 HTTP/HTTPS 代理：`127.0.0.1:8888`；自动代理配置 URL：`http://127.0.0.1:8090/proxy.pac`。服务端需使用匹配的 proxy 模式、密码和混淆类型。

全局 IPv4：

```bash
sudo ./socks5proxy_client_darwin_arm64 \
  -mode tunnel -transport tcp \
  -server SERVER_IP:1443 -server-name vpn.example.com \
  -client-id desktop -token-file ./desktop.token -ca ./server.crt
```

需要预先配置 TLS TCP 隧道服务端、令牌和 CA。

## 文档与边界

发布前完成本地 race/vet/staticcheck、十种桌面二进制构建、Apple Silicon 原生 HTTP/CONNECT/SOCKS5/PAC 实测；Linux 低 FD 400 次连接回收和三种全局 TUN（QUIC、TLS TCP、每日令牌表）集成测试均通过。[验证记录](https://github.com/shikanon/socks5proxy/blob/v0.2.0/docs/proxy-scopes-verification-2026-11-01.md)包含完整范围。

- [全局代理和网站通配符规则](https://github.com/shikanon/socks5proxy/blob/v0.2.0/docs/proxy-scopes.md)
- [隧道部署](https://github.com/shikanon/socks5proxy/blob/v0.2.0/docs/tunnel.md)
- [每日令牌表](https://github.com/shikanon/socks5proxy/blob/v0.2.0/docs/token-table.md)
- [数据映射原理](https://github.com/shikanon/socks5proxy/blob/v0.2.0/docs/data-mapping.md)

HTTPS 规则匹配主机名，不能匹配加密路径。全局 TUN 不承载 IPv6；macOS/Windows 有 IPv6 阻断策略，Linux 需自行限制 IPv6。更具体的局域网/主机路由优先。移动端仍只提供全局 IPv4；Windows/macOS TUN 未新增真机网络验收。
