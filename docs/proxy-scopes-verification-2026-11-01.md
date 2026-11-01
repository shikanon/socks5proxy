# v0.2.0 发布前验证

2026-11-01，使用 Go 1.26.0 在 macOS Apple Silicon 本地完成编译与应用代理实测，并在 Linux 隔离网络命名空间内完成 TUN 和资源回收验证。

## 本地检查

| 检查 | 结果 |
| --- | --- |
| `go test -race -timeout 60s ./...` | 全部通过 |
| `go vet ./...` | 通过 |
| staticcheck v0.8.2 | 通过 |
| gofmt、`git diff --check`、构建/集成脚本 Bash 语法 | 通过 |
| 六种客户端目标：darwin/linux/windows × amd64/arm64 | 全部构建成功 |
| Linux/Windows amd64/arm64 服务端 | 全部构建成功 |
| 原生 macOS arm64 客户端 | Mach-O arm64，`-version` 输出 `v0.2.0` |

本地构建目录为 `dist/v0.2.0-local/`，与历史 dist 产物隔离。Windows/macOS TUN 未新增真机网络验收，跨平台构建成功不等于所有平台的系统网络实测。

## Apple Silicon 二进制运行

直接运行新编译的 macOS arm64 客户端，以及本地构建的原生服务端：

```bash
python3 scripts/test-proxy-scopes.py \
  --client "$PWD/dist/v0.2.0-local/socks5proxy_client_darwin_arm64" \
  --server /tmp/s5p-tools/native-server \
  --js-runtime '/Applications/Trae CN.app/Contents/MacOS/Electron' \
  --version v0.2.0
```

JavaScript 使用本地 Node.js 22.21.1 兼容运行时。最终输出：

```text
CLI scopes/PAC passed: HTTP, CONNECT, SOCKS5, remote/direct, no fallback, version and shutdown
```

实测使用 TCP 中继统计远程连接数，证明未命中规则时不连接远程、命中时连接远程；停止远程监听后，未命中目标仍可访问，命中目标返回 HTTP 502 / SOCKS 失败，目标访问计数不增加。PAC 实际在 JavaScript 中执行，覆盖大小写、末尾点号、根域名、多级子域名、`?`、IDNA 和非匹配域名。Go 集成测试另覆盖真实 HTTPS、流式大请求、CONNECT 预读数据及半关闭。

## Linux 资源回收

在 `106.13.216.217` 的临时测试目录运行更新后的 `test-proxy-resources.py`，只对测试子进程施加 FD 限制，不修改宿主进程的限制。

| 条件 | 结果 |
| --- | --- |
| RLIMIT_NOFILE / 会话上限 / 短连接次数 | 64 / 16 / 400 |
| 远程拨号失败前/峰值/结束 FD | 7 / 7 / 7 |
| 不完整握手，客户端/服务端峰值 FD | 23 / 7 |
| 不完整握手回收后 FD | 7 / 7 |
| 400 次成功短连接结束后 FD | 7 / 7 |
| 有等待字节的连接时 SIGTERM | 两端退出码 0 |

旧测试在未发送目标地址时假设客户端立刻拨远程。网址分流需要先读取目标，现改为发送完整 SOCKS CONNECT，再检查远程拒绝后的错误响应、EOF 和 FD 回收；保留原来的不完整握手压力测试。

## 全局 IPv4 TUN

使用独立客户端、服务端、目标网络命名空间，依次运行：

```bash
TUNNEL_TRANSPORT=tcp-table bash scripts/test-tunnel-linux.sh
TUNNEL_TRANSPORT=tcp bash scripts/test-tunnel-linux.sh
TUNNEL_TRANSPORT=quic bash scripts/test-tunnel-linux.sh
```

三种传输均通过以下验证：

- 未开隧道时客户端无法直接访问目标。
- 隧道内 HTTP 1 MiB 文件下载，SHA-256 一致。
- ICMP 三发三收：TCP/table 为 1280 字节 IP 包，QUIC 为 1150 字节。
- UDP/TCP DNS 与 1、512、1122、4096 字节 UDP 回显。
- 停止服务端后访问被阻断；重启服务端后现有客户端自动重连并校验文件。
- 停止客户端后路由与原快照一致；服务端 NAT/FORWARD 规则和恢复状态清理成功。

最后分别输出 `transport=tcp-table obfs=none`、`transport=tcp obfs=random`、`transport=quic obfs=random` 的通过记录。宿主默认路由没有被替换，测试 namespace 由脚本退出清理。国内至海外的令牌表真实连通性记录见[此前实测](token-table-verification-2026-10-24.md)。
