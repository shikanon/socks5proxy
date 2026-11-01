# 全局 IPv6 双栈验证 — 2026-11-01

本次源码新增可选 IPv4 + IPv6 全局隧道。两端启用 `-ipv6`，默认 MTU 为 1280；默认 IPv4 模式仍为 1150。IPv6 内层可以通过 IPv4 或 IPv6 外层传输。现有 v0.2.1 Release 不包含此改动，本文记录当前工作区源码的验证结果。

## Linux 端到端验收

在获授权的 Linux amd64 测试主机上从源码构建两端，使用三个独立 network namespace，未修改宿主默认路由、DNS 或防火墙。测试主机没有公网 IPv6 默认路由，本次验证为隔离网络中的双栈转发与 NAT66，不代表公网 IPv6 已验收。

| 模式 | 外层端点 | 物理 MTU | TUN MTU | 结果 |
| --- | --- | --- | --- | --- |
| QUIC + random，双栈 | IPv4 | 1280 | 1280 | 通过 |
| TCP TLS + random，双栈 | IPv4 | 1280 | 1280 | 通过 |
| TCP table + none，双栈 | IPv4 | 1280 | 1280 | 通过 |
| QUIC + random，双栈 | IPv6 | 1280 | 1280 | 通过 |
| QUIC + random，默认 IPv4 | IPv4 | 1228 | 1150 | 通过 |

双栈用 `2001:db8:1::/64` 作为外层网段、`2001:db8:2::/64` 作为目标网段，以及默认 `fd00:5:5::/64` 隧道网段。防火墙明确阻断客户端物理接口直接转发到目标，连接前确认 HTTP 无法直达。

每组双栈验收均检查：

- IPv4 与 IPv6 HTTP 下载 1 MiB 文件，SHA256 与原文件一致。
- IPv4 ICMP 完整 1280 字节，ICMPv6 1232 字节载荷 + 8 字节 ICMPv6 头 + 40 字节 IPv6 头，共 1280 字节；每轮 3/3 成功。
- IPv4/IPv6 UDP 和 TCP DNS 查询；IPv6 使用 AAAA 问题，校验完整返回报文。
- IPv4 UDP 回显 1、512、1122、4096 字节；IPv6 回显 1、512、1232、4096 字节，两端启用 IPv6 源分片，校验逐字节一致。
- 外层端点路由仍使用物理 veth，IPv6 外层保留 `/128` 绕行。
- 服务端正常停止后，IPv4/IPv6 访问失败；防火墙规则和策略、IPv4 forwarding、IPv6 forwarding 与出口 `accept_ra` 与启动前一致。
- 同一服务端重启后，现有客户端自动重连；IPv6 HTTP/DNS/UDP/ICMP 再次通过，IPv4 文件下载哈希一致，客户端双栈路由与重连前相同。
- 客户端正常停止后，IPv4/IPv6 路由与原快照一致。

快照比较使用 `iptables -S` 和 `ip6tables -S` 的 filter/nat 规则与策略，避免将内核保留的空 NAT 表或累积计数误判为未恢复。服务端恢复状态文件也必须删除。

namespace 测试使用 `-linux-dns=false`，直接向测试 DNS 地址发送查询，避免通过共享 D-Bus 改写宿主 DNS。系统 resolver 的实际切换不在这项端到端验收范围内。

Linux root 环境可从仓库根目录复现：

```bash
sudo env "PATH=$PATH" TUNNEL_IPV6=true TUNNEL_TRANSPORT=quic \
  bash scripts/test-tunnel-linux.sh
sudo env "PATH=$PATH" TUNNEL_IPV6=true TUNNEL_TRANSPORT=tcp \
  bash scripts/test-tunnel-linux.sh
sudo env "PATH=$PATH" TUNNEL_IPV6=true TUNNEL_TRANSPORT=tcp-table \
  bash scripts/test-tunnel-linux.sh
sudo env "PATH=$PATH" TUNNEL_IPV6=true TUNNEL_ENDPOINT_IPV6=true \
  bash scripts/test-tunnel-linux.sh
sudo env "PATH=$PATH" bash scripts/test-tunnel-linux.sh
```

CI 新增四组双栈矩阵，原 IPv4 检查保留；本地已运行对应矩阵，尚未触发远端 CI。

## 协议、核心与编译检查

Go 1.26.0 下，macOS arm64 和 Linux amd64 的 `go test -race -timeout 60s ./...`、`go vet ./...` 均通过；macOS 的 `staticcheck ./...` 通过。Shell 语法、Python 语法与 `git diff --check` 通过。

新增及扩展测试覆盖 IPv6 报文长度、扩展头/源分片、类型与地址族一致性、协商缺失/错误、每个 IPv6 参数的证明绑定、稳定租约及会话替换、地址伪造过滤、移动端双栈收发与重连参数变化、IPv6 外层 socket 保护，以及三个桌面平台网络计划的逐步失败恢复。真实 QUIC 测试禁用路径 MTU 探测，在最小路径上双向传输 1280/1400 字节 IP 包，并验证分片乱序、重复、冲突、过期和内存上限。

`scripts/build-desktop.sh` 以 `VERSION=ipv6-dev` 构建 10 个产物成功：Darwin/Linux/Windows 的 amd64、arm64 客户端，以及 Linux/Windows 的 amd64、arm64 服务端。服务端的系统网络配置只支持 Linux，Windows 服务端编译成功不表示 Windows TUN 服务端受支持。

Apple Silicon 客户端已运行 `-version` 和帮助参数，确认包含 `-ipv6`、`-dns6` 与双栈 MTU 说明。产物位于本机 `/tmp/s5p-ipv6-desktop/`，未生成新 Release。

## 平台与公网边界

| 范围 | 此次证据 |
| --- | --- |
| Linux 双栈 TUN/NAT66/路由恢复 | 上述五组实测通过 |
| macOS / Windows 全局 IPv6 | 网络计划、失败恢复测试及交叉编译通过；未运行原生双栈 VPN 联网 |
| Android | Go 核心双栈测试通过；原生 IPv6 开关和 VpnService 配置已实现，本机缺 Android SDK，此次未构建 APK 或真机联网 |
| iOS | Go 核心测试及 Swift 语法解析通过；此次未完成 XCFramework/原生应用构建或真机 VPN 联网 |
| 公网 IPv6 / RA 默认路由 | 测试服务器无公网 IPv6 默认路由；`accept_ra` 调整顺序与恢复有测试，实际 RA 路由保留及公网访问未实测 |

部署参数、默认 NAT66 和外部路由前缀配置见[双栈使用说明](tunnel.md#启用-ipv4--ipv6-双栈)。更具体的现有系统路由仍优先；重连保留隧道路由不等于独立的系统 kill switch。
