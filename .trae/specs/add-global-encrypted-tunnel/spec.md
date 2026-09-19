# macOS 与 Windows 全局加密隧道 Spec

## Why

当前项目仅提供应用级 HTTP/SOCKS5 TCP 代理，且 `simple` / `random` 只是流量混淆，无法让未配置代理的应用自动接入，也不能提供现代密码学意义上的机密性和完整性。需要新增基于系统 TUN 设备的全局隧道模式，使 macOS 和 Windows 客户端的默认 IPv4 流量经加密通道到达 Linux 服务端，由服务端解密后转发。

## What Changes

- 在现有客户端和服务端命令中新增 `tunnel` 模式，同时完整保留当前 `proxy` 模式、`simple` / `random` 简易加密（流量混淆）实现及其参数和线协议兼容性。
- 客户端通过 macOS `utun` 或 Windows Wintun 创建三层虚拟网卡，接管默认 IPv4 流量。
- 客户端和服务端使用 QUIC 1-RTT 数据报承载 IP 包，并强制使用 TLS 1.3 提供加密、完整性和服务端身份校验。
- 隧道可在 TLS 保护内对 IP 数据包额外应用 `simple` / `random` 混淆；默认 `none`，安全能力始终由 QUIC/TLS 1.3 提供。
- 新增加密控制流，完成协议版本协商、客户端令牌认证、虚拟 IPv4 地址分配、MTU 和 DNS 参数下发。
- Linux 服务端创建 TUN 设备，校验并注入客户端 IP 包，通过系统转发和 NAT 访问目标网络，再将返回包发送给对应客户端。
- 客户端安装服务端地址豁免路由、隧道默认路由和 DNS 配置；正常退出、启动失败及下次启动检测到残留状态时恢复原配置。
- 隧道断开后默认保持路由并持续重连，避免流量明文回落；用户主动停止时恢复系统网络。
- 首期仅承载 IPv4。隧道启用期间阻断非链路本地 IPv6 默认流量，防止 IPv6 绕过隧道；IPv6 全隧道作为后续能力。
- 更新构建发布流程，产出 macOS amd64/arm64、Windows amd64 客户端和 Linux amd64 服务端；Windows 发布包包含官方签名的 Wintun 运行时及许可证。

## Impact

- Affected specs: 客户端全局隧道、加密传输、客户端认证、跨平台网络配置、Linux 转发/NAT、发布与运维
- Affected code:
  - `cmd/client/main.go`
  - `cmd/server/main.go`
  - `internal/tunnel/**`
  - `.github/workflows/ci.yml`
  - `.github/workflows/release.yml`
  - `README.md`
  - `docs/tunnel.md`
  - `go.mod`
  - `go.sum`
- Runtime dependencies:
  - QUIC 实现：`github.com/quic-go/quic-go`
  - 跨平台 TUN：`golang.zx2c4.com/wireguard/tun`
  - Windows Wintun 官方签名 DLL
- Operational prerequisites:
  - macOS/Windows 客户端必须以管理员权限运行。
  - Linux 服务端必须以 root 或具备 `CAP_NET_ADMIN` 运行。
  - 服务端 UDP 监听端口必须可达。

## Architecture

### Data path

1. 客户端先通过物理网卡连接服务端 UDP 地址并完成 TLS 1.3 握手。
2. 客户端在首个双向 QUIC 控制流中发送认证请求；认证成功后获取虚拟地址、DNS 和 MTU。
3. 客户端记录当前网络状态，创建 TUN，添加服务端地址的物理网关 `/32` 豁免路由，再安装隧道路由和 DNS。
4. 从客户端 TUN 读取的每个 IPv4 包按已协商的 `none` / `simple` / `random` 处理后，作为一个 QUIC DATAGRAM 发送。
5. 服务端先完成 QUIC/TLS 解密，再按协商模式还原数据包；只接受源地址等于该会话获配虚拟地址的合法 IPv4 包，并写入 Linux TUN。
6. Linux 内核转发并 NAT；返回包从服务端 TUN 读出后，根据目标虚拟地址找到会话并发送 QUIC DATAGRAM。
7. 客户端校验返回包目标地址后写回 TUN，由操作系统交给原应用。

### Tunnel protocol v1

- ALPN 固定为 `socks5proxy-tunnel/1`。
- QUIC 必须开启 DATAGRAM 扩展，双方不支持时立即终止，不能回退到明文或旧混淆协议。
- TLS 最低和最高版本均为 TLS 1.3；客户端必须验证系统信任链或 `-ca` 指定的 CA，并校验 `-server-name`。
- 不启用 0-RTT，认证和数据只能在 TLS 握手完成后发送。
- 每条 QUIC 连接只允许一个控制流。控制消息使用 4 字节大端长度前缀加 JSON，单条消息最大 64 KiB。
- `auth_request` 字段为 `version`、`client_id`、`token`、`obfs`；`auth_response` 字段为 `version`、`session_id`、`client_ipv4`、`server_ipv4`、`mtu`、`dns_ipv4`、`obfs`。
- 数据报格式为 `version(1) | type(1) | raw_ipv4_packet`；v1 中 `version=1`、`type=1`。
- `obfs` 只允许 `none`、`simple`、`random`，默认 `none`。协商值受 TLS 控制流保护，服务端不允许该模式时必须拒绝认证，不能静默降级。
- 选择 `simple` / `random` 时，只混淆数据报中的 `raw_ipv4_packet`，协议头、认证消息和控制消息不应用该变换。
- TUN 默认 MTU 为 1280，可配置范围为 576 至 1400。超过协商 MTU、长度字段不一致或非 IPv4的数据报必须丢弃并限速记录。
- 服务端令牌文件每行格式为 `<client_id>:<sha256-hex>`，忽略空行和 `#` 注释。令牌原文至少 32 个随机字节；服务端比较令牌摘要时使用常量时间比较，且任何日志都不得输出令牌。

## ADDED Requirements

### Requirement: 模式兼容与配置校验

系统 SHALL 在客户端和服务端新增 `-mode proxy|tunnel`，默认值保持 `proxy`，确保现有启动命令行为不变。

隧道客户端 SHALL 支持 `-server`、`-client-id`、`-token-file`、`-ca`、`-server-name`、`-dns`、`-mtu`、`-state-dir` 和 `-obfs none|simple|random`。隧道服务端 SHALL 支持 `-local`、`-cert`、`-key`、`-token-file`、`-tunnel-cidr`、`-dns`、`-mtu`、`-outbound-interface`、`-manage-network` 和 `-obfs-allow`。

代理模式 SHALL 继续支持 `-type simple|random`、`-passwd`、`-recv http|socks5`、`-local` 和 `-server`，并保留 `CreateSimpleCipher`、`CreateRandomCipher`、`CreateAuth`、`Encrypt`、`Decrypt`、`EncodeWrite`、`DecodeRead` 的现有可调用行为。

#### Scenario: 旧代理命令保持兼容

- **WHEN** 用户未设置 `-mode` 并使用现有 HTTP 或 SOCKS5 参数启动
- **THEN** 系统 SHALL 继续进入当前代理模式，且不创建 TUN 或修改系统路由

#### Scenario: simple 简易加密继续可用

- **WHEN** 客户端和服务端均以代理模式及 `-type simple`、相同 `-passwd` 启动
- **THEN** 双方 SHALL 按现有线协议完成编码、解码和代理转发

#### Scenario: random 简易加密继续可用

- **WHEN** 客户端和服务端均以代理模式及 `-type random`、相同 `-passwd` 启动
- **THEN** 双方 SHALL 按现有线协议完成编码、解码和代理转发

#### Scenario: 隧道配置不完整

- **WHEN** 隧道模式缺少服务端证书、令牌文件、客户端标识或可达的 UDP 地址
- **THEN** 系统 SHALL 在修改网络配置前返回明确错误并退出

### Requirement: 安全传输与身份认证

系统 SHALL 使用经 TLS 1.3 保护的 QUIC 连接传输控制消息和所有隧道 IP 包。系统 MAY 在 TLS 内层使用 `simple` / `random` 混淆 IP 数据包，但 SHALL NOT 将其用作 TLS 的替代加密。

#### Scenario: 合法客户端建立隧道

- **WHEN** 客户端信任服务端证书、服务器名称匹配且令牌摘要匹配
- **THEN** 服务端 SHALL 建立已认证会话并返回唯一虚拟 IPv4 地址

#### Scenario: 证书校验失败

- **WHEN** 服务端证书不受信、过期或名称不匹配
- **THEN** 客户端 SHALL 中止连接，且 SHALL NOT 创建 TUN 或修改系统路由

#### Scenario: 令牌无效

- **WHEN** `client_id` 不存在或令牌摘要不匹配
- **THEN** 服务端 SHALL 返回通用认证失败并关闭连接，不泄露客户端是否存在

#### Scenario: TLS 内层启用 simple 或 random

- **WHEN** 客户端请求的 `obfs` 在服务端允许列表中
- **THEN** 服务端 SHALL 在 TLS 控制流中确认相同模式，双方只对 QUIC DATAGRAM 的 IP 包负载执行对应变换

#### Scenario: 混淆模式不被允许

- **WHEN** 客户端请求的 `obfs` 不在服务端允许列表中
- **THEN** 服务端 SHALL 拒绝会话，不能降级到 `none` 或其他模式

### Requirement: 客户端全局 IPv4 接管

客户端 SHALL 在 macOS 与 Windows 上创建 TUN 设备，将默认 IPv4 流量导入隧道，并为服务端公网 IP 保留经原物理网关的 `/32` 路由以避免路由递归。

本期“全局”指默认 IPv4 路由和 DNS 流量；环回、链路本地及访问物理网关所必需的本地链路流量保持直连。

#### Scenario: 启用全局隧道

- **WHEN** 客户端完成 TLS 和令牌认证
- **THEN** 客户端 SHALL 依次持久化原网络状态、创建 TUN、安装服务端豁免路由、安装两条覆盖默认 IPv4 的隧道路由并切换 DNS

#### Scenario: 服务端使用域名

- **WHEN** `-server` 使用域名
- **THEN** 客户端 SHALL 在改路由前解析并固定本次连接使用的服务端 IP，并为该 IP 创建豁免路由

#### Scenario: IPv6 可用

- **WHEN** 主机存在非链路本地 IPv6 默认路由而 v1 隧道只支持 IPv4
- **THEN** 客户端 SHALL 在隧道期间安装可恢复的 IPv6 阻断规则，防止流量绕过

### Requirement: DNS 防泄漏

客户端 SHALL 使用服务端下发或 `-dns` 覆盖的 IPv4 DNS 地址，并确保到该地址的请求经过 TUN。

#### Scenario: 隧道运行

- **WHEN** 系统应用执行 DNS 查询
- **THEN** 查询 SHALL 使用隧道 DNS 配置并通过加密隧道发送

#### Scenario: 隧道停止

- **WHEN** 用户正常停止客户端
- **THEN** 原 DNS 配置 SHALL 被完整恢复

### Requirement: 路由事务与故障恢复

客户端 SHALL 将每一次系统网络修改作为可回滚事务，状态文件必须在首个修改动作之前原子写入。

#### Scenario: 启动中途失败

- **WHEN** 创建 TUN、添加路由或设置 DNS 任一步骤失败
- **THEN** 客户端 SHALL 按逆序撤销本次已完成操作并返回非零状态

#### Scenario: 进程异常退出后重新启动

- **WHEN** 客户端发现同一状态目录中的未完成事务
- **THEN** 客户端 SHALL 先恢复残留网络配置，再尝试建立新隧道

#### Scenario: 隧道意外断开

- **WHEN** 已启用隧道后 QUIC 连接中断
- **THEN** 客户端 SHALL 保持隧道路由以阻止明文回落，并以带抖动的指数退避持续重连

#### Scenario: 用户主动停止

- **WHEN** 客户端收到 SIGINT、SIGTERM 或 Windows 控制台中断事件
- **THEN** 客户端 SHALL 停止收发、删除隧道配置、恢复 DNS 与路由并删除事务状态文件

### Requirement: Linux 服务端解密、校验与转发

服务端 SHALL 在 Linux 上创建一个 TUN 设备，从地址池为并发客户端分配唯一 IPv4 地址，并根据返回包目标地址分发到正确会话。

#### Scenario: 客户端发送合法包

- **WHEN** 已认证会话发送源地址等于获配地址且长度合法的 IPv4 包
- **THEN** 服务端 SHALL 解密、校验并写入服务端 TUN

#### Scenario: 客户端伪造源地址

- **WHEN** 会话发送源地址不等于获配地址的包
- **THEN** 服务端 SHALL 丢弃该包并记录不含负载的安全事件

#### Scenario: 返回包到达服务端 TUN

- **WHEN** 返回 IPv4 包的目标地址对应在线客户端
- **THEN** 服务端 SHALL 将包只发送至该客户端会话

#### Scenario: 地址池耗尽

- **WHEN** 没有可分配的客户端地址
- **THEN** 服务端 SHALL 拒绝新会话而不影响现有会话

### Requirement: 服务端网络管理

服务端 SHALL 在 `-manage-network=true` 时启用 IPv4 转发，并添加仅作用于隧道 CIDR 和指定出口网卡的 NAT/转发规则；退出时只删除自身创建的规则并恢复由自身修改的原值。

#### Scenario: 自动网络配置

- **WHEN** 服务端以足够权限启动且出口网卡存在
- **THEN** 服务端 SHALL 配置 TUN 地址、IPv4 转发及带唯一注释标识的 NAT/转发规则

#### Scenario: 外部管理网络

- **WHEN** 用户设置 `-manage-network=false`
- **THEN** 服务端 SHALL 不修改 sysctl 或防火墙，并在转发前置条件不满足时给出诊断信息

### Requirement: 数据包边界与资源限制

系统 SHALL 保留一个 IP 包对应一个 QUIC DATAGRAM 的边界，并限制控制消息、会话数量、待发送队列和单包大小。

#### Scenario: 慢客户端或发送队列拥塞

- **WHEN** 某客户端发送队列达到上限
- **THEN** 服务端 SHALL 丢弃该会话的新数据包并增加丢包计数，不能阻塞其他会话

#### Scenario: 畸形数据包

- **WHEN** 收到版本错误、长度错误、非 IPv4 或超过 MTU 的数据报
- **THEN** 接收端 SHALL 丢弃数据报，且进程 SHALL 保持运行

### Requirement: 可观测性

系统 SHALL 使用结构化字段记录会话生命周期和累计计数，不记录 IP 包负载、令牌、私钥或完整 DNS 查询内容。

#### Scenario: 会话结束

- **WHEN** 客户端断开或被服务端关闭
- **THEN** 双方 SHALL 记录会话标识、客户端标识、持续时间、收发字节数和丢包数

### Requirement: 构建、发布与文档

项目 SHALL 提供可重复构建和平台编译检查，并记录管理员权限、证书、令牌、Linux NAT、Wintun、启动/停止和故障恢复步骤。

#### Scenario: 创建发布版本

- **WHEN** 发布工作流由版本标签触发
- **THEN** Release SHALL 包含 macOS amd64/arm64 客户端、Windows amd64 客户端及 Wintun 文件、Linux amd64 服务端和统一 SHA256 校验文件

## MODIFIED Requirements

### Requirement: 加密能力表述

现有 `simple` / `random` 简易加密实现 SHALL 保留，不得删除、重命名、改变密钥派生/替换表算法或破坏客户端与服务端线协议兼容性。代理模式继续通过原有 `-type` 选择；隧道模式通过独立的 `-obfs` 在 QUIC/TLS 1.3 内层选择。只有 QUIC + TLS 1.3 通道可描述为安全加密隧道；`simple` / `random` 在两种模式中都明确标记为流量混淆。

### Requirement: 客户端与服务端入口

`cmd/client` 和 `cmd/server` SHALL 根据 `-mode` 分派到现有代理实现或新增隧道实现。共享入口 SHALL 负责参数校验、信号取消和退出码，具体隧道逻辑 SHALL 位于 `internal/tunnel`。

## REMOVED Requirements

无。

## Non-Goals

- 首期不提供 GUI、托盘图标、自动更新或安装器。
- 首期不承载 IPv6；运行时以阻断 IPv6 默认流量避免泄漏。
- 首期不提供按应用、按域名或按 CIDR 的分流策略。
- 首期不替代企业 PKI、账号系统或集中式密钥管理；使用证书和静态令牌文件。
- 首期不承诺穿透仅允许 TCP 的网络，也不回退到 TCP 隧道。
- 首期不改变现有 HTTP/SOCKS5 代理协议及 `simple` / `random` 的兼容行为。
