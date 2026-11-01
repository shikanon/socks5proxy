# 全局加密隧道

全局隧道通过 Linux TUN、macOS `utun` 或 Windows Wintun 接管默认 IPv4 流量；两端启用 `-ipv6` 后同时接管默认 IPv6 流量。IP 包传输到 Linux 服务端，再通过 Linux 转发和 NAT 访问目标网络。TCP、UDP、ICMP/ICMPv6 和 DNS 都通过同一个 IP 隧道承载。

默认保持 QUIC + TLS 1.3。`simple` / `random` 仅是可选流量混淆，不提供加密安全性；默认 `-obfs none`。

| 两端 `-transport` 参数 | 外层传输 | 安全性 |
| --- | --- | --- |
| `quic`（默认） | UDP / QUIC DATAGRAM | TLS 1.3 |
| `tcp` | TCP 长连接，按长度封装 IP 包 | TLS 1.3，严格验证证书和 ALPN |
| `tcp-plain` | 同样的 TCP 长连接及封包 | 显式无加密、无数据完整性 |
| `tcp-table` | TCP 长连接，UTC 日期 + 每日字节替换 | 无需 TLS 的学习用令牌表，无数据完整性 |

`tcp-table` 由服务端自动生成 256 项、每项 8–16 位的随机令牌表，两端共享该文件，结合 UTC 当日零点时间戳生成每日数据映射。它支持同一套 TUN 全局路由、TCP/UDP/ICMP/DNS、NAT 和断线重连；不需要证书或额外长令牌。启动与表文件同步见[每日令牌表隧道](token-table.md)。

UDP 线路丢包严重时可尝试 `tcp`。关闭 TLS 是否更快需要同条件重复测量；对网络受限的传输，TLS 开销通常不是主要瓶颈。TCP 外层丢包会暂停其后所有 IP 包，并可能与内层 TCP 重传叠加，因此也不保证适合所有线路。

## 前置条件

- 服务端：Linux、root 或 `CAP_NET_ADMIN`、可用的 `ip`、`iptables` 和 `sysctl`。
- 客户端：Linux root、macOS 或 Windows 管理员权限。Linux 需要 `ip`、运行中的 `systemd-resolved`、`resolvectl`，以及使用 resolved stub（127.0.0.53/54）的 `/etc/resolv.conf`。
- 网络：`quic` 需要服务端 UDP 端口；`tcp` / `tcp-plain` / `tcp-table` 需要 TCP 端口。两端必须选择相同后端。
- Windows：`wintun.dll` 必须与客户端 EXE 位于同一目录。Release 中的 Windows ZIP 已包含它。
- 双栈服务端还需要 `ip6tables`、内核 IPv6/NAT 支持和可用的 IPv6 出口路由。隧道承载 IPv6 不要求外层连接也使用 IPv6，可以连接 IPv4 服务端地址。
- 默认 IPv4 模式保持原行为：macOS/Windows 运行期间阻断公网和 ULA IPv6，Linux 需要自行禁用或限制 IPv6。启用双栈后安装 IPv6 路由，不再应用这些 IPv6 阻断规则。

## 准备 TLS 证书

生产环境应使用受客户端信任的证书。测试环境可以创建私有 CA：

```bash
openssl req -x509 -newkey rsa:3072 -nodes \
  -keyout ca.key -out ca.crt -days 3650 \
  -subj "/CN=Socks5Proxy Test CA"

openssl req -newkey rsa:3072 -nodes \
  -keyout server.key -out server.csr \
  -subj "/CN=vpn.example.com"

printf '%s\n' \
  'subjectAltName=DNS:vpn.example.com,IP:203.0.113.10' \
  'extendedKeyUsage=serverAuth' > server.ext

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt -days 825 -extfile server.ext
```

客户端的 `-server-name` 必须匹配证书中的 DNS 名称或 IP SAN。不要分发 `ca.key` 或 `server.key`。
`tcp-plain` 和 `tcp-table` 不加载证书；`tcp` 始终使用 TLS，不会因缺少证书或握手失败而改用其他模式。下面的长令牌准备流程用于 `quic` / `tcp` / `tcp-plain`；`tcp-table` 直接使用共享令牌表。

## 准备客户端令牌

每个客户端使用独立、至少 32 字节的随机令牌：

```bash
openssl rand -hex 32 > desktop.token
chmod 600 desktop.token

TOKEN_HASH="$(tr -d '\r\n' < desktop.token | shasum -a 256 | awk '{print $1}')"
printf 'desktop:%s\n' "$TOKEN_HASH" > clients.tokens
chmod 600 clients.tokens
```

客户端保存令牌原文，服务端只保存 SHA-256 摘要。不要在命令行直接传递令牌。
计算摘要时必须排除令牌文件末尾的换行；直接对 `desktop.token` 文件运行 `sha256sum` 会把换行计入摘要，导致认证失败。

TCP 后端共用三步认证：服务端 32 字节随机挑战，客户端随机 nonce 和 HMAC-SHA256 证明，服务端签名认证响应。证明绑定混淆模式和下发的 IP、DNS、MTU、会话参数，拒绝旧挑战重放。线路上不会直接发送长期令牌、令牌表或摘要。服务端摘要是 TCP 认证的等价凭据，必须像令牌一样保护。

## 启动 Linux 服务端

确认出口网卡名称：

```bash
ip -4 route show default
```

以 `eth0` 为例：

```bash
sudo ./socks5proxy_server_linux_amd64 \
  -mode tunnel \
  -local :443 \
  -cert ./server.crt \
  -key ./server.key \
  -token-file ./clients.tokens \
  -tunnel-cidr 10.255.0.0/24 \
  -dns 1.1.1.1 \
  -outbound-interface eth0 \
  -obfs-allow none,simple,random
```

服务端会创建 `socks5tun0`，启用 IPv4 转发，并添加仅作用于隧道 CIDR 和指定出口网卡的 iptables 规则。退出时会删除自身规则并恢复原 `ip_forward` 值。

已有防火墙和 NAT 管理系统时，使用 `-manage-network=false`，并自行配置：

- 隧道 CIDR 的双向 FORWARD。
- 隧道 CIDR 到出口网卡的 MASQUERADE。
- `net.ipv4.ip_forward=1`。

此选项仍由程序配置 TUN 地址、MTU 和链路状态，仅跳过转发 sysctl 与防火墙/NAT 管理。

## 启用 IPv4 + IPv6 双栈

在前述令牌、CA 和证书准备完成后，Linux 服务端示例：

```bash
sudo ./socks5proxy_server_linux_amd64 \
  -mode tunnel -ipv6 \
  -local :443 -cert ./server.crt -key ./server.key \
  -token-file ./clients.tokens \
  -outbound-interface eth0 \
  -tunnel-cidr6 fd00:5:5::/64 \
  -dns6 2606:4700:4700::1111
```

macOS Apple Silicon 客户端示例：

```bash
sudo ./socks5proxy_client_darwin_arm64 \
  -mode tunnel -ipv6 \
  -server vpn.example.com:443 -server-name vpn.example.com \
  -ca ./ca.crt -client-id desktop -token-file ./desktop.token
```

Linux/Windows 客户端使用相同参数；移动端勾选界面的 IPv6 开关。两端可同时添加 `-transport tcp`，或使用 `tcp-table` 的共享表认证方式并添加 `-ipv6`。双栈支持四种 tunnel 传输；`tcp-plain` / `tcp-table` 的安全边界不变。

| 参数 | 默认值 / 要求 |
| --- | --- |
| 两端 `-ipv6` | 默认关闭；客户端请求后，服务端必须支持，否则在安装路由前失败 |
| 服务端 `-tunnel-cidr6` | `fd00:5:5::/64`；网络地址必须对齐，前缀长度 64–96，允许 ULA 或全局单播 |
| 服务端 `-dns6` | `2606:4700:4700::1111` |
| 客户端 `-dns6` | 可覆盖服务端下发的 IPv6 DNS；必须同时启用 IPv6 |
| 双栈 `-mtu` | 默认 1280，允许 1280–1400；IPv4 模式默认仍为 1150 |

IPv6 地址从稳定的 IPv4 租约偏移派生，默认服务端地址为 `fd00:5:5::1`；源地址必须匹配当前客户端租约。IPv6 不会转换成 IPv4：访问 IPv6 目标时，服务端出口必须能访问该目标地址。部署前检查：

```bash
ip -6 addr show dev eth0
ip -6 route show default
curl -6 --noproxy '*' https://example.com/
```

默认网络管理为隧道前缀添加窄范围 `ip6tables` FORWARD 与 MASQUERADE（NAT66），并启用 `net.ipv6.conf.all.forwarding`。若出口的 `accept_ra=1`，程序先改为 2，使转发开启后仍可接收 RA；停止时恢复原值、转发状态和自身规则。既有更早的 DROP 规则仍可能阻止转发。

使用运营商/上游明确路由到服务器的独立 IPv6 前缀时，可通过 `-manage-network=false -tunnel-cidr6 YOUR_ROUTED_PREFIX` 改为外部管理：自行配置 IPv4/IPv6 forwarding、防火墙，以及上游到隧道前缀的回程路由；IPv6 可不使用 NAT66。不要把普通出口网卡的同网段直接用作隧道前缀，除非另外正确配置上游路由或 NDP。

服务器地址可为 IPv4、域名或带方括号的 IPv6，例如 `-server '[2001:db8::10]:443'`；示例文档地址须替换为实际地址。客户端优先选择域名的 IPv4 结果，无 IPv4 时使用 IPv6，并为外层端点保留物理出口的 `/32` 或 `/128` 路由。短暂断线且保留 TUN 时复用该地址；自动回退到直连后会重新解析域名。TLS 仍需正确的 DNS/IP SAN。

双栈桌面客户端安装 IPv4 和 IPv6 各两个 `/1` 路由，已有更具体的局域网/主机路由仍优先。默认在断线超时后恢复两种地址族的原路由与 DNS；`-disconnect-policy block` 可在断线期间持续保留双栈隧道路由。

## 启动 macOS 客户端

```bash
sudo ./socks5proxy_client_darwin_arm64 \
  -mode tunnel \
  -server vpn.example.com:443 \
  -server-name vpn.example.com \
  -ca ./ca.crt \
  -client-id desktop \
  -token-file ./desktop.token \
  -obfs none
```

Intel Mac 使用 `socks5proxy_client_darwin_amd64`。

## 启动 Linux 客户端

使用与 macOS 相同的参数运行 `socks5proxy_client_linux_amd64`。
客户端在 TUN 上设置服务端下发的 DNS 和 `~.` 路由域，并清空旧缓存；正常停止时撤销 TUN DNS 并再次清空缓存，物理网卡 DNS 保持原设置。
`-dns` 可覆盖服务端下发的 IPv4 DNS，双栈时 `-dns6` 可覆盖 IPv6 DNS；两种 DNS 都通过 TUN 配置。

不使用 systemd-resolved 的环境需要自行配置隧道 DNS，再使用 `-linux-dns=false`。
网络 namespace 集成测试也必须使用此参数，避免 namespace 中的 `resolvectl` 通过共享 D-Bus 修改宿主 DNS。

## 启动 Windows 客户端

在管理员 PowerShell 中运行：

```powershell
.\socks5proxy_client_windows_amd64.exe `
  -mode tunnel `
  -server vpn.example.com:443 `
  -server-name vpn.example.com `
  -ca .\ca.crt `
  -client-id desktop `
  -token-file .\desktop.token `
  -obfs none
```

保持 `wintun.dll` 与 EXE 在同一目录。程序会创建 Wintun 适配器，记录并切换默认物理接口 DNS，停止时恢复原 DNS。

## TLS 内层混淆

客户端可选择：

```text
-obfs none
-obfs simple
-obfs random
```

服务端通过 `-obfs-allow` 设置允许列表。`quic` / `tcp` 在 TLS 控制流中协商，TCP 认证证明也绑定模式；不匹配时连接失败，不会静默降级。

数据路径为：

```text
IP 包 -> simple/random（可选）-> QUIC DATAGRAM 或 TCP 长度封包
QUIC DATAGRAM 或 TCP 长度封包 -> simple/random 还原（可选）-> IP 包
```

`quic` 和 `tcp` 的数据安全性来自 TLS 1.3。TCP 混淆使用令牌摘要的十六进制表示作为输入；QUIC 保留旧版混淆协议兼容性。

## 使用 TCP 后端

将上述服务端和客户端命令都添加 `-transport tcp`，并设置可用 TCP 端口，例如 `-local :1443` / `-server vpn.example.com:1443`。其他令牌、证书、TUN、DNS、NAT 参数保持相同。`-obfs random` 可用于 `quic` / `tcp` / `tcp-plain`；`tcp-table` 必须使用 `-obfs none`。

测试无 TLS 性能时，在两端显式选择 `-transport tcp-plain`，并使用独立的随机测试令牌及服务端摘要文件。此模式不需要 `-cert` / `-key` / `-ca` / `-server-name`。启动日志会提示无加密；随机混淆不阻止监听、数据篡改或主动中继，认证证明也不为后续 IP 包提供完整性。

TCP 控制认证总预算为 10 秒，完成后转入双向 IP 封包模式。2 字节网络序长度后接完整数据报，最大 1402 字节；零长度为传输内部心跳，不会写入 TUN。传输层每 15 秒发送空帧，接收空闲 45 秒、单次写入 10 秒超时后关闭连接。新版桌面客户端默认每 2 秒通过隧道发送 IP DNS 探测，并与支持的服务端协商 ping/pong；实际转发或心跳连续 10 秒失去有效响应后开始恢复直连，不必等待传输层空闲超时。旧转发线程结束后才启用新连接。探测配置与预算见[自动回退说明](watchdog.md)。

QUIC 和 TCP 可由不同进程同时监听，但每个实例需要独立的端口、`-tun-name`、`-tunnel-cidr`、双栈 `-tunnel-cidr6` 和 `-state-dir`。多个实例共用宿主网络时，应由统一的网络管理配置转发/NAT（实例使用 `-manage-network=false`），避免各自恢复全局转发状态。

传统 `-mode proxy -recv socks5 -type random` 仅代理应用流量，可作为性能对照。它不接管系统 IP，也不能代替全局隧道的 UDP/ICMP 承载。

## 停止与恢复

使用 `Ctrl+C` 正常停止。客户端会删除隧道路由、恢复 DNS 和 IPv6 状态。

桌面客户端默认 `-disconnect-policy direct`，在远端静默超时或断线超过预算时自动执行同样的网络恢复，关闭 TUN 并丢弃旧队列。恢复成功后，普通流量使用原来的物理路由和 DNS；认证及健康检查成功后重新创建隧道。首次启动时远端不可达也保持直连。恢复命令失败时记录 `error` 并重试，不提前报告直连成功。

| 客户端参数 | 默认值 | 含义 |
| --- | --- | --- |
| `-disconnect-policy` | `direct` | 超时恢复直连；`block` 保留隧道路由持续重连 |
| `-fallback-timeout` | `10s` | 无有效转发响应或心跳的期限；显式断线后的重连宽限 |
| `-health-interval` | `2s` | IP DNS 和协商后的 ping/pong 检查间隔 |
| `-health-dns-name` | `example.com` | 用于检查的 A/AAAA 域名，需能通过隧道 DNS 解析 |
| `-reconnect-interval` | `5s` | 直连状态连接失败后的等待时间 |
| `-daemon` | 关闭 | 独立父进程监督客户端并在其退出后恢复网络、重启 |
| `-config` | 无 | JSON 客户端配置；显式命令行参数覆盖文件中的对应配置 |

检测期限到达后开始恢复，路由/DNS 系统命令本身还需要执行时间。控制心跳正常但转发故障也会触发回退；旧服务端没有心跳时仍使用普通 IP DNS 探测。启用双栈时两个地址族都须通过探测；认证和转发检查通过前不会安装客户端路由。已有连接可能需要应用重试。移动端生命周期和 `proxy` / PAC 行为不随此桌面功能改变。

客户端在修改系统网络前写入恢复状态：

- macOS/Linux 默认路径：`/var/run/socks5proxy/network-state.json`
- Windows 默认路径：`%ProgramData%\socks5proxy\network-state.json`

使用 `-daemon` 时，独立父进程会在子进程异常退出后恢复残留配置，再启动替代进程。未使用守护进程时，以相同 `-state-dir` 再次启动也会先恢复再连接。开机启动、示例配置、状态查询与日志见[守护进程部署](watchdog.md)。

也可在没有运行中客户端时主动恢复：

```bash
sudo ./socks5proxy_client_darwin_arm64 -recover-network
sudo ./socks5proxy_client_darwin_arm64 -status
```

Linux/Windows 替换为对应二进制，并保持管理员权限。自定义状态目录时两条命令都要添加原来的 `-state-dir`，或使用同一 `-config`。`-status` 的 `running` 表示客户端锁是否被占用；`mode` 是最后一次保存的状态。`block` 只保留断线期间的路由，不提供完整的系统 kill switch。

## 排障

- TLS 名称错误：检查 `-server-name` 是否存在于证书 SAN。
- `authentication failed`：检查客户端 ID、令牌原文和服务端摘要是否匹配。
- `create TUN device` 失败：确认管理员权限；Windows 确认 `wintun.dll` 与架构匹配。
- 无法访问互联网：确认所选后端对应的 UDP/TCP 端口、防火墙 FORWARD、NAT 和出口网卡名称。
- IPv4 模式默认 MTU 为 1150，IPv4-only QUIC 会将更大的 MTU 限制为 1150。双栈默认 1280，允许 1280–1400；协商双栈后的 QUIC 对较大的封装数据报分片/重组，不依赖外层路径 MTU 探测。TCP IPv4 模式允许 576–1400；比较后端性能时使用相同 MTU。IPv4 大 UDP 包由内核分片/重组；IPv6 大 UDP 需要发送端进行源分片，路由器不替 IPv6 分片。
- Linux DNS 配置失败：检查 `resolvectl status` 及 `/etc/resolv.conf`；启用后应能看到 TUN 的 DNS 和 `~.` 路由域。
- IPv4 可用、IPv6 不通：确认两端启用 `-ipv6`，服务端 IPv6 出口路由、`ip6tables` 和 NAT66 可用；仅分配 ULA 隧道地址不能提供公网 IPv6。验收范围见[IPv6 验证记录](ipv6-verification-2026-11-01.md)。
