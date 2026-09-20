<img src="./img/logo.png" width="600">

# Socks5Proxy

[![GitHub license](https://img.shields.io/github/license/shikanon/socks5proxy)](https://github.com/shikanon/socks5proxy/blob/master/LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/shikanon/socks5proxy)](https://github.com/shikanon/socks5proxy/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/shikanon/socks5proxy)](https://github.com/shikanon/socks5proxy/network)
[![Language](https://img.shields.io/badge/Language-Go-blue.svg)](https://golang.org/)
[![Go Report Card](https://goreportcard.com/badge/github.com/shikanon/socks5proxy)](https://goreportcard.com/report/github.com/shikanon/socks5proxy)


用golang 实现了一个简单的socks5协议来实现代理转发，主要应用场景是給公司内部做VPN登陆，提供内网访问。*(声明：由于采用的是原始的socks5协议，并没有对协议做改造加工，并不一定能防范GFW的主动探测，请勿用于非法用途)*

项目同时支持两种运行模式：

- `proxy`：HTTP/SOCKS5 TCP 应用代理，支持 HTTP 转发、HTTPS CONNECT 和 `simple` / `random` 流量混淆。
- `tunnel`：Linux/macOS/Windows 全局 IPv4 TUN，以及 Android VpnService / iOS Packet Tunnel 原生客户端，默认使用 QUIC + TLS 1.3；可选 TCP + TLS 1.3（`-transport tcp`）或显式无加密 TCP（`-transport tcp-plain`），支持 `none` / `simple` / `random` 混淆。

## 客户端平台

| 平台 | 架构 | 使用入口 |
| --- | --- | --- |
| Linux | amd64、arm64 | CLI，TUN 模式需要 root / 网络管理权限 |
| Windows | amd64、arm64 | CLI，以管理员身份运行；使用包含对应 Wintun DLL 的 ZIP |
| macOS | Intel、Apple Silicon | CLI，TUN 模式需要 sudo |
| Android 8.0+ | arm64、armv7、x86_64 | 原生配置界面 + VpnService；构建 APK 后安装 |
| iOS / iPadOS 15+ | arm64；模拟器 arm64、x86_64 | SwiftUI + NetworkExtension；真机需 Apple 签名 |

桌面发布物由 Release workflow 构建；移动源码、AAR/XCFramework 和应用构建入口见[移动客户端文档](./docs/mobile-clients.md)。移动端目前提供全局 IPv4 隧道，尚无真机联网验收；IPv6 被阻断。应用签名和商店分发由使用者配置。

## 安全说明

- 当前 `simple` / `random` 仅用于流量混淆，不是安全加密，也不提供现代意义上的机密性、完整性或重放防护。
- 全局隧道默认 `quic`，以及可选的 `tcp`，使用 TLS 1.3；不会自动降级为明文。`tcp-plain` 不提供 IP 包机密性或完整性，即使使用 `random` 也是如此。
- 两个 TCP 后端使用新鲜随机挑战和 HMAC 认证，线路上传输认证证明，不直接发送令牌或摘要。摘要本身等价于 TCP 认证凭据，应保密；明文模式仍可被监听、篡改或中继，应使用独立测试令牌。
- 不要把 `simple` / `random` 当作 TLS、SSH、WireGuard 或 AEAD 安全通道的替代品。
- `proxy` 密码最终只影响至多 256 张替换表，长密码不能提升其密码学强度。本地监听无用户认证，默认只绑定 `127.0.0.1:8888`；服务端没有目标地址 ACL，部署时应限制访问来源和出口。
- TLS 隧道保护客户端至服务端这一段；服务端仍可看到解封装的流量。目标站点的数据保护依赖 HTTPS 等端到端协议。完整边界见[安全与威胁模型](./docs/security.md)。


文件结构
```
cryptogram.go       `流量混淆算法`
socks5.go           `socks5协议实现`
server.go           `服务端实现`
client.go           `客户端实现`
cmd/server/main.go  `服务端主启动程序`
cmd/client/main.go  `客户端主启动程`
internal/tunnel/    `全局加密隧道、TUN 和系统网络配置`
mobile/            `可嵌入的 Go 隧道核心，gomobile 绑定接口`
apps/android/      `Android 原生 VPN 应用`
apps/ios/          `iOS 原生应用与 Packet Tunnel 扩展`
```


- [SOCKS5协议介绍](./docs/socks5.md)
- [流量混淆算法介绍](./docs/cryptogram.md)
- [全局加密隧道部署](./docs/tunnel.md)
- [软件下载及版本说明](./docs/release.md)
- [Android / iOS 构建与使用](./docs/mobile-clients.md)
- [应用代理与同机部署](./docs/proxy.md)
- [安全与威胁模型](./docs/security.md)
- [连接、资源与网络排障](./docs/troubleshooting.md)

#### 使用说明

从 [GitHub Releases](https://github.com/shikanon/socks5proxy/releases) 下载对应系统/架构的产物并[校验 SHA256SUMS](./docs/release.md)。Release 可能落后于源码；下面也提供从仓库根目录运行的方式（Go 版本见 `go.mod`）。

客户端和服务端可以在同一台机器运行，使用两个不同端口。分别在两个终端执行：

```bash
# 终端 1：服务端
go run ./cmd/server -mode proxy -local 127.0.0.1:18888 -type random -passwd demo-only
# 终端 2：客户端
go run ./cmd/client -mode proxy -local 127.0.0.1:8888 \
  -server 127.0.0.1:18888 -type random -passwd demo-only -recv http
```

```bash
curl --noproxy "" --proxy http://127.0.0.1:8888 https://example.com/
```

浏览器设置 HTTP/HTTPS 代理为 `127.0.0.1:8888`。若客户端改为 `-recv socks5`，浏览器也必须选择 SOCKS5，curl 使用 `--proxy socks5h://127.0.0.1:8888`。代理目标不能指回这两个监听端口。跨机器部署时，客户端的 `-server` 改为服务端地址；完整说明见[应用代理部署](./docs/proxy.md)。

`-passwd` **没有默认值，必须显式设置**；`-type` 默认 `random`，两端必须相同。客户端 `-recv` 默认 `http`。应用代理只处理主动配置代理的应用；全局 IPv4 流量请使用[隧道模式](./docs/tunnel.md)。

两端 proxy 模式均支持以下资源参数：

| 参数 | 默认值 | 含义 |
| --- | --- | --- |
| `-max-connections` | `256` | 每个进程的最大活动会话数，额外连接留在系统监听队列 |
| `-dial-timeout` | `10s` | 上游/目标连接及 DNS 的超时 |
| `-handshake-timeout` | `10s` | 从接收连接到完成协议协商的总预算 |
| `-idle-timeout` | `5m` | 双向均无流量时回收连接 |

握手总预算包含连接时间；这些参数为 `0` 时使用默认值，负数无效。每会话约占用两个 FD，低 `ulimit -n` 环境应下调并发上限，详见[资源排障](./docs/troubleshooting.md)。`Ctrl+C` 会关闭监听及活动会话并等待退出。

## TODO

- [x] 明确 `simple` / `random` 仅用于流量混淆，不作为安全加密承诺（[#23](https://github.com/shikanon/socks5proxy/issues/23)）
- [x] 迁移 CI 到 GitHub Actions，并补齐格式化 / 测试 / vet / staticcheck（[#25](https://github.com/shikanon/socks5proxy/issues/25)）
- [x] 将发布物迁移到 GitHub Releases，并提供 `SHA256SUMS`（[#28](https://github.com/shikanon/socks5proxy/issues/28)）
- [x] 补充 README 的安全声明与威胁模型说明（[#29](https://github.com/shikanon/socks5proxy/issues/29)）
- [x] 说明客户端与服务端同机部署的使用方式（[#2](https://github.com/shikanon/socks5proxy/issues/2)）
- [x] 排查并缓解 `socket: too many open files` 问题（[#3](https://github.com/shikanon/socks5proxy/issues/3)）
- [x] 更新下载与使用说明，覆盖最新发布方式与问题排查入口（[#4](https://github.com/shikanon/socks5proxy/issues/4)）

实现细节、复现与验证结果见 [README TODO 验证记录](./docs/verification-readme-todos-2026-09-20.md)。
