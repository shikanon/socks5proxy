# 全局代理与指定网址代理

客户端有两种流量范围。`-mode tunnel` 为系统全局隧道，默认 IPv4，两端启用 `-ipv6` 后支持 IPv4 + IPv6，覆盖 TCP、UDP、ICMP/ICMPv6 和 DNS，不需要应用逐个设置代理；`-mode proxy -proxy-scope rules` 按目标网站域名分流，命中规则走远程服务端，其余由客户端直连。

`proxy` 默认 `-proxy-scope all`，表示进入本地 HTTP/SOCKS5 端口的全部 TCP 连接走远程。它仍需要应用配置代理，不能代替系统 TUN。

| 需求 | 客户端参数 | 应用设置 |
| --- | --- | --- |
| 系统全局 IPv4 | `-mode tunnel` | 无需 HTTP/SOCKS 代理设置；需要 sudo/root/管理员 |
| 系统全局 IPv4 + IPv6 | `-mode tunnel -ipv6`，服务端也启用 IPv6 | 同上；服务端需 IPv6 出口 |
| 已配置代理的应用全部走远程 | `-mode proxy -proxy-scope all` | 指向本地 HTTP/SOCKS5 入口 |
| 指定网站走远程、其余直连 | `-mode proxy -proxy-scope rules` | 本地 HTTP/SOCKS5 入口，或浏览器/系统 PAC |

## 全局模式

macOS Apple Silicon 示例，使用已有 TLS TCP 服务端：

```bash
sudo ./socks5proxy_client_darwin_arm64 \
  -mode tunnel -transport tcp \
  -server SERVER_IP:1443 -server-name vpn.example.com \
  -client-id desktop -token-file ./desktop.token -ca ./server.crt
```

服务端必须运行对应的 `-mode tunnel -transport tcp`，不能指向原有 proxy 端口。CA、令牌和服务端完整配置见[全局隧道部署](tunnel.md)。若使用学习用每日令牌表：

```bash
sudo ./socks5proxy_client_darwin_arm64 \
  -mode tunnel -transport tcp-table \
  -server SERVER_IP:24443 -client-id desktop \
  -table-file ./token-table.json
```

该表必须先由服务端生成并复制至客户端，两端身份一致，见[令牌表说明](token-table.md)。

全局模式安装两个 IPv4 `/1` 路由，启用 `-ipv6` 时另外安装 `::/1` 和 `8000::/1`，保留远程隧道端点的物理出口；已有更具体的局域网/主机路由仍优先。IPv6 目标需要服务端具备 IPv6 出口，外层连接可以是 IPv4 或 IPv6。双栈命令、NAT66 与路由前缀部署见[隧道部署](tunnel.md#启用-ipv4--ipv6-双栈)。

默认 IPv4 模式仍保留 macOS/Windows 和移动端的 IPv6 阻断策略，Linux 需自行限制 IPv6。停止客户端会恢复管理的路由、DNS 和相关状态。现有系统更具体路由及其他 VPN 可能影响结果，详见[网络排障](troubleshooting.md)。不要同时把本项目 proxy 配置在同一个 TUN 出口上。

桌面 TUN 默认开启断线自动回退：`-disconnect-policy direct -fallback-timeout 10s -health-interval 2s -reconnect-interval 5s`。通过隧道 DNS 探测实际转发路径，超时后撤销 TUN 路由、DNS 和程序添加的 IPv6 阻断规则，普通流量恢复原来的出口；心跳正常但转发故障也会回退。远端认证及转发探测恢复后自动重新启用隧道。添加 `-daemon` 可以在客户端崩溃后由独立进程恢复网络并重启。超时语义与开机启动见[守护进程说明](watchdog.md)。

若开发过程中需要 AI coding 始终通过自己的网络出口，可只在目标应用配置本地 HTTP/SOCKS5 代理，或者使用下面的网站规则，保留开发工具所用域名直连。当前 TUN 不提供按进程选择代理；自动回退能恢复断线后的新连接，已中断的会话仍需应用重试。`proxy` / PAC 远程失败的行为保持下文所述，不会由 TUN 守护进程改写系统代理设置。

## 指定网站与通配符

跨机器部署先启动应用代理服务端：

```bash
./socks5proxy_server_linux_amd64 \
  -mode proxy -local :18888 -type random -passwd demo-only
```

macOS 客户端无需 sudo：

```bash
./socks5proxy_client_darwin_arm64 \
  -mode proxy -server SERVER_IP:18888 -type random -passwd demo-only \
  -recv http -local 127.0.0.1:8888 \
  -proxy-scope rules \
  -proxy-domains 'example.com,*.example.org,api?.example.net' \
  -pac-listen 127.0.0.1:8090
```

将 `SERVER_IP` 和学习用密码替换为自己的配置，两端 `-type`、`-passwd` 一致。密码仅用于字节混淆，不提供安全加密。

| 规则 | 命中 | 不命中 |
| --- | --- | --- |
| `example.com` | `example.com` | `www.example.com` |
| `*.example.com` | 根域名、`www.example.com`、`a.b.example.com` | `example.com.evil` |
| `api?.example.net` | `api1.example.net` | `api.example.net`、`api12.example.net` |
| `api*.example.*` | `api.example.com`、`api12.example.co.uk` | `www.example.com` |
| `*` | 全部目标主机 | — |
| `127.0.0.1` / `::1` | 对应 IP | 其他 IP |

`*` 匹配零个或多个字符，可以跨越点号；`?` 匹配单个字符。大小写及末尾点号不影响匹配，国际化域名转换为 IDNA/punycode。`*.example.com` 特别包含根域名。规则不会自动包含网站使用的 CDN、登录域名或第三方资源，需要分别添加。

支持根网址，例如 `https://example.com/`、`https://*.example.com/*`；会提取主机名，匹配该主机所有端口、HTTP 和 HTTPS。带端口的规则也按主机匹配，端口不作为过滤条件。HTTPS CONNECT 只提供目标主机，无法识别加密 URL 路径，所以 `/private/*`、查询参数、fragment 和用户名密码形式会报错。含 `?` 通配符的规则请使用裸域名。

规则文件一行一条，忽略空行和行首 `#` 注释：

```text
# websites.txt
example.com
*.example.org
api?.example.net
```

启动时使用 `-rules-file ./websites.txt`，可与 `-proxy-domains` 合并，重复条目会去重。仓库提供[示例规则文件](../examples/proxy-domains.txt)。单文件最多 1 MiB，合并去重后最多 1024 条；启动时加载，修改后重启客户端。`rules` 模式必须有至少一条规则；`all` 模式不能附带网站规则。

## 浏览器与 PAC

有两种配置方式：

1. 手动设置 HTTP 和 HTTPS 代理为 `127.0.0.1:8888`。所有请求进入客户端，由客户端按规则选择远程或直连。
2. 将自动代理配置 URL 设为 `http://127.0.0.1:8090/proxy.pac`。浏览器根据同一份规则决定是否进入本地代理；未命中直接访问。

macOS 在“系统设置 → 网络 → 当前网络服务 → 详细信息 → 代理 → 自动代理配置”填写上述 PAC URL，或在浏览器代理配置中填写。客户端只提供 PAC 文件，不自动修改系统设置；启用和关闭由使用者控制。应用是否采用系统 PAC 取决于应用本身，curl 不解释 PAC；用 curl 验证时显式指定本地代理：

```bash
curl --noproxy '' --proxy http://127.0.0.1:8888 https://example.com/
curl --noproxy '' --proxy http://127.0.0.1:8888 https://unmatched.example/
curl --noproxy '*' http://127.0.0.1:8090/proxy.pac
```

PAC 监听和启用 PAC 时的代理监听都必须是回环 IP，不能是 `0.0.0.0`；建议显式使用 `127.0.0.1`。文件只允许 GET/HEAD，不调用 DNS。命中规则只返回 `PROXY host:port`，不附加 `DIRECT`；远程失败时客户端返回 HTTP 502 / SOCKS 失败，不主动改成直连。浏览器可能有独立的 PAC 故障恢复策略，PAC 不承担系统防泄漏保障。

`-recv socks5` 对应 PAC 的 `SOCKS5` 指令，需浏览器支持。手动 SOCKS5 客户端应保留域名，例如 curl `socks5h://127.0.0.1:8888`。若应用先解析域名再向代理传 IP，客户端只能匹配 IP，无法还原原域名；命中域名的连接在远程解析，未命中的连接在本机解析。

全局 TUN 不支持网站规则/PAC 参数，携带这些参数会在修改网络前报错。移动端提供全局 IPv4 和可选 IPv6 双栈，网址规则只适用于桌面应用代理和 Go `ClientContext`。
