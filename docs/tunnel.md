# 全局加密隧道

全局隧道通过 Linux TUN、macOS `utun` 或 Windows Wintun 接管默认 IPv4 流量，使用 QUIC + TLS 1.3 传输到 Linux 服务端。服务端解密后将 IP 包写入 TUN，并通过 Linux 转发和 NAT 访问目标网络。

`simple` / `random` 可以作为 TLS 内层的可选流量混淆，但不会替代 TLS。默认使用 `-obfs none`。

## 前置条件

- 服务端：Linux、root 或 `CAP_NET_ADMIN`、可用的 `ip`、`iptables` 和 `sysctl`。
- 客户端：Linux root、macOS 或 Windows 管理员权限。Linux 需要 `ip`、运行中的 `systemd-resolved`、`resolvectl`，以及使用 resolved stub（127.0.0.53/54）的 `/etc/resolv.conf`。
- 网络：客户端能够访问服务端监听的 UDP 端口。
- Windows：`wintun.dll` 必须与客户端 EXE 位于同一目录。Release 中的 Windows ZIP 已包含它。
- 当前隧道仅承载 IPv4；macOS/Windows 运行期间会阻断公网和 ULA IPv6。Linux 尚未自动阻断 IPv6，需要在宿主网络中另行禁用或限制 IPv6。

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

- `socks5tun0` 的地址和链路状态。
- 隧道 CIDR 的双向 FORWARD。
- 隧道 CIDR 到出口网卡的 MASQUERADE。
- `net.ipv4.ip_forward=1`。

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
`-dns` 可覆盖服务端下发的 IPv4 DNS。

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

服务端通过 `-obfs-allow` 设置允许列表。模式在 TLS 加密的认证控制流中协商；不匹配时连接失败，不会静默降级。

数据路径为：

```text
IP 包 -> simple/random（可选）-> QUIC/TLS 1.3
QUIC/TLS 1.3 -> simple/random 还原（可选）-> IP 包
```

`simple` / `random` 不提供完整性、可靠身份认证或重放防护，隧道安全性始终来自 TLS 1.3。

## 停止与恢复

使用 `Ctrl+C` 正常停止。客户端会删除隧道路由、恢复 DNS 和 IPv6 状态。

客户端在修改系统网络前写入恢复状态：

- macOS/Linux 默认路径：`/var/run/socks5proxy/network-state.json`
- Windows 默认路径：`%ProgramData%\socks5proxy\network-state.json`

进程异常退出后，以相同 `-state-dir` 再次启动；程序会先恢复残留配置，再连接服务端。

隧道已启用后发生网络中断时，客户端保留隧道路由并持续重连，避免业务流量回落到物理默认路由。

## 排障

- TLS 名称错误：检查 `-server-name` 是否存在于证书 SAN。
- `authentication failed`：检查客户端 ID、令牌原文和服务端摘要是否匹配。
- `create TUN device` 失败：确认管理员权限；Windows 确认 `wintun.dll` 与架构匹配。
- 无法访问互联网：确认服务端 UDP 端口、防火墙 FORWARD、NAT 和出口网卡名称。
- 默认 MTU 为 1150。服务端会将更大的 `-mtu`（包括旧配置的 1280）限制为 1150，并把实际值下发给客户端。这为 QUIC 最小 1200 字节 UDP 载荷预留封装开销，不依赖路径 MTU 探测成功。IPv4 大 UDP 包由内核分片/重组；TCP 按实际 TUN MTU 分段。
- Linux DNS 配置失败：检查 `resolvectl status` 及 `/etc/resolv.conf`；启用后应能看到 TUN 的 DNS 和 `~.` 路由域。
