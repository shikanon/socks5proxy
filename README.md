<img src="./img/logo.png" width="600">

# Socks5Proxy

[![GitHub license](https://img.shields.io/github/license/shikanon/socks5proxy)](https://github.com/shikanon/socks5proxy/blob/master/LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/shikanon/socks5proxy)](https://github.com/shikanon/socks5proxy/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/shikanon/socks5proxy)](https://github.com/shikanon/socks5proxy/network)
[![Language](https://img.shields.io/badge/Language-Go-blue.svg)](https://golang.org/)
[![Go Report Card](https://goreportcard.com/badge/github.com/shikanon/socks5proxy)](https://goreportcard.com/report/github.com/shikanon/socks5proxy)


用golang 实现了一个简单的socks5协议来实现代理转发，主要应用场景是給公司内部做VPN登陆，提供内网访问。*(声明：由于采用的是原始的socks5协议，并没有对协议做改造加工，并不一定能防范GFW的主动探测，请勿用于非法用途)*

项目同时支持两种运行模式：

- `proxy`：原有 HTTP/SOCKS5 应用代理，继续支持 `simple` / `random` 简易加密（流量混淆）。
- `tunnel`：Linux/macOS/Windows 全局 IPv4 TUN，默认使用 QUIC + TLS 1.3；可选 TCP + TLS 1.3（`-transport tcp`）或显式无加密 TCP（`-transport tcp-plain`），支持 `none` / `simple` / `random` 混淆。

## 安全说明

- 当前 `simple` / `random` 仅用于流量混淆，不是安全加密，也不提供现代意义上的机密性、完整性或重放防护。
- 全局隧道默认 `quic`，以及可选的 `tcp`，使用 TLS 1.3；不会自动降级为明文。`tcp-plain` 不提供 IP 包机密性或完整性，即使使用 `random` 也是如此。
- 两个 TCP 后端使用新鲜随机挑战和 HMAC 认证，线路上传输认证证明，不直接发送令牌或摘要。摘要本身等价于 TCP 认证凭据，应保密；明文模式仍可被监听、篡改或中继，应使用独立测试令牌。
- 不要把 `simple` / `random` 当作 TLS、SSH、WireGuard 或 AEAD 安全通道的替代品。


文件结构
```
cryptogram.go       `流量混淆算法`
socks5.go           `socks5协议实现`
server.go           `服务端实现`
client.go           `客户端实现`
cmd/server/main.go  `服务端主启动程序`
cmd/client/main.go  `客户端主启动程`
internal/tunnel/    `全局加密隧道、TUN 和系统网络配置`
```


- [SOCKS5协议介绍](./docs/socks5.md)
- [流量混淆算法介绍](./docs/cryptogram.md)
- [全局加密隧道部署](./docs/tunnel.md)
- [软件下载及版本说明](./docs/release.md)

#### 使用说明

以下参数说明为兼容保留的 `proxy` 模式。macOS/Windows 全局隧道请参阅[全局加密隧道部署](./docs/tunnel.md)。

**服务端**
在服务器端中启动路径，打开。/cmd/server/，运行`go run main.go`
服务端命令参数有三个：
```
  -local string #设置服务器对外端口
    	Input server listen address(Default 8888): (default ":18888")
  -passwd string #设置服务器对外密码
    	Input server proxy password: (default "123456")
  -type string #设置流量混淆类型
    	Input traffic obfuscation type (simple/random, not secure encryption): (default "random")
```

**客户端**
在客户端中启动路径，打开。/cmd/client/，运行`go run main.go`
服务端命令参数有四个：
```
  -local string #设置客户端的本地转发端口
        Input server listen address(Default 8888): (default ":8888")
  -passwd string #设置服务器的密码
        Input server proxy password: (default "123456")
  -server string #设置服务器ip地址和端口
        Input server listen address, for example: 16.158.6.16:18181
  -type string #设置流量混淆类型
    	Input traffic obfuscation type (simple/random, not secure encryption): (default "random")
  -recv string #设置上游协议模式
    	Upstream protocol mode: http or socks5 (default http)
```

## TODO

- [x] 明确 `simple` / `random` 仅用于流量混淆，不作为安全加密承诺（[#23](https://github.com/shikanon/socks5proxy/issues/23)）
- [x] 迁移 CI 到 GitHub Actions，并补齐格式化 / 测试 / vet / staticcheck（[#25](https://github.com/shikanon/socks5proxy/issues/25)）
- [x] 将发布物迁移到 GitHub Releases，并提供 `SHA256SUMS`（[#28](https://github.com/shikanon/socks5proxy/issues/28)）
- [ ] 补充 README 的安全声明与威胁模型说明（[#29](https://github.com/shikanon/socks5proxy/issues/29)）
- [ ] 说明客户端与服务端同机部署的使用方式（[#2](https://github.com/shikanon/socks5proxy/issues/2)）
- [ ] 排查并缓解 `socket: too many open files` 问题（[#3](https://github.com/shikanon/socks5proxy/issues/3)）
- [ ] 更新下载与使用说明，覆盖最新发布方式与问题排查入口（[#4](https://github.com/shikanon/socks5proxy/issues/4)）
