# 断线自动直连与守护进程

桌面 TUN 客户端默认监测远端状态。远端失联超过期限后，程序撤销自身管理的路由、DNS 和 IPv6 阻断设置，关闭 TUN 并丢弃旧发送队列；之后普通流量使用原来的系统网络，不再由该 TUN 接管。直连期间继续尝试远端，认证及健康检查成功后重新创建隧道。

此功能适用于 Linux、macOS、Windows 桌面 TUN。`proxy` / PAC 和 Android/iOS 原生 VPN 生命周期保持原行为。已有 v0.2.1 发布物不包含本功能，需要使用本次源码构建客户端；服务端更新后可额外协商控制心跳。

## 默认行为与参数

| 参数 | 默认值 | 行为 |
| --- | --- | --- |
| `-disconnect-policy` | `direct` | 到期限恢复普通直连；`block` 在断线期间保留隧道路由 |
| `-fallback-timeout` | `10s` | 失去有效转发响应或控制心跳的期限；显式断线后的重连宽限 |
| `-health-interval` | `2s` | 发送 IP DNS 探测及协商后的 ping/pong |
| `-health-dns-name` | `example.com` | 向隧道 DNS 查询 A；双栈同时经 IPv6 DNS 查询 AAAA |
| `-reconnect-interval` | `5s` | 直连状态连接失败后等待多久再尝试；也用于守护进程重启等待 |
| `-daemon` | 关闭 | 独立父进程监督客户端，父进程仍在前台；后台和开机启动使用系统服务 |
| `-config` | 无 | JSON 配置文件；也自动选择 tunnel 模式 |
| `-status` | 关闭 | 输出最后保存的状态及客户端是否运行，然后退出 |
| `-recover-network` | 关闭 | 在没有运行中客户端时恢复状态文件记录的网络，然后退出 |

首次启动时先认证，再通过现有数据连接发送 IP DNS 包，验证服务端 TUN、转发/NAT、DNS 查询及响应路径；全部检查成功后才创建客户端 TUN 和修改路由。转发故障持续期间保持直连，每次重试仍先探测，避免认证成功就重新接管网络。

隧道建立后，如果连接明确断开，会先保留 TUN 尝试重连；在 10 秒宽限内重连成功可继续使用它。每个启用的地址族必须持续得到有效 DNS 答复，协商了心跳时还必须收到对应随机 nonce 的 pong。任一路径连续 10 秒没有有效响应，立即开始恢复，不再追加一轮宽限；心跳正常也不能掩盖转发故障。重连拨号和检查受剩余期限限制。

探测使用服务端提供的 DNS，客户端设置 `-dns` / `-dns6` 时使用覆盖值。响应必须匹配地址、端口、随机事务 ID 和问题，并包含成功的 A/AAAA 答案（允许 CNAME）；SERVFAIL、空答案和截断响应不计为健康。探测回答在客户端内部消费，不写入应用 TUN。`health_dns_name` 应选择有稳定 A 记录、双栈时同时有 AAAA 记录的可解析域名，仅接受 ASCII 主机名。该探测代表 DNS 和相应 IP 转发路径可用，不能保证每个站点或端口都可达。

期限表示开始恢复的时间，系统路由/DNS 命令还需要执行时间，单轮恢复预算为 15 秒。恢复失败时保存 `error`，保留未完成的撤销步骤并再次尝试；恢复成功前不会重新接管流量或报告 `direct`。普通物理网络必须原本可用；已中断的 TCP/AI coding 会话可能需要应用重试，不能透明迁移既有连接。

参数允许范围：`fallback-timeout` 为 200ms–5m，`health-interval` 为 100ms 到回退期限的一半，`reconnect-interval` 为 100ms–5m。测试可使用 `3s / 500ms / 500ms`，日常默认值对瞬时抖动更宽容。

旧服务端未协商 `heartbeat` 时仍兼容，日志会提示 `server lacks heartbeat support`；普通 IP DNS 探测仍执行，因此转发故障不必等待旧 TCP 45 秒接收空闲超时。服务端及其 DNS 必须能正常处理探测。TLS 证书验证失败不会切换到明文后端。

## 直接运行

在原来的桌面隧道命令后添加 `-daemon` 即可启用独立监督。下面是 macOS Apple Silicon 示例，服务端需已按[隧道部署](tunnel.md)准备好：

```bash
sudo ./socks5proxy_client_darwin_arm64 \
  -mode tunnel -transport tcp \
  -server vpn.example.com:443 -server-name vpn.example.com \
  -ca ./server.crt -client-id desktop -token-file ./client.token \
  -disconnect-policy direct -fallback-timeout 10s \
  -health-interval 2s -reconnect-interval 5s -daemon
```

Linux/Windows 使用相应二进制和管理员权限；双栈在两端启用 `-ipv6`。守护进程持有单独的锁，客户端也持有网络所有权锁。子进程死亡后，父进程先读取恢复日志、恢复网络，再启动替代进程。正常停止时父进程通知子进程退出；20 秒未退出则结束子进程并执行恢复。Windows 使用结束进程后恢复的方式。

使用 `Ctrl+C` 停止前台守护进程。不要为两个活动客户端配置同一状态目录，也不要为两个不同状态目录的客户端设置冲突的 TUN 或全局路由。

## JSON 配置

仓库提供[配置示例](../examples/watchdog-client.json)。替换服务端地址和凭据文件，不在配置或命令行写令牌原文：

```json
{
  "transport": "tcp",
  "server": "vpn.example.com:443",
  "server_name": "vpn.example.com",
  "client_id": "desktop",
  "token_file": "client.token",
  "ca": "server.crt",
  "ipv6": false,
  "disconnect_policy": "direct",
  "fallback_timeout": "10s",
  "health_interval": "2s",
  "health_dns_name": "example.com",
  "reconnect_interval": "5s",
  "obfs": "none"
}
```

```bash
sudo ./socks5proxy_client_darwin_arm64 -config /绝对路径/client.json -daemon
```

`token_file`、`table_file`、`ca`、`state_dir` 的相对路径以配置文件所在目录为基准。显式 CLI 参数覆盖对应文件字段，例如 `-config client.json -disconnect-policy block`。时长使用字符串，如 `"10s"`；拒绝未知字段和多个 JSON 对象，文件最多 64 KiB。

其他可选字段为 `dns`、`dns6`、`mtu`、`tun_name`、`skip_linux_dns`。`dns6` 需要启用 IPv6；Linux 默认管理 systemd-resolved，只有外部管理 DNS 时设置 `"skip_linux_dns": true`。`tcp-table` 使用 `"table_file": "token-table.json"` 和 `"obfs": "none"`，无需 `token_file` / `ca`，表文件仍须保密。

## 安装为系统后台服务

安装器为 `scripts/client-daemon.py`，需要 Python 3、绝对配置路径和构建好的客户端。`install` 会创建系统定义、启用开机启动并立即启动；不覆盖同名现有服务。`render` 只输出定义，不安装、不运行客户端，也不修改网络，可用于预览：

```bash
python3 scripts/client-daemon.py render --platform darwin \
  --binary /Library/Socks5Proxy/client \
  --config /Library/Socks5Proxy/client.json
```

`--platform` 仅用于 `render`，支持 `darwin`、`linux`、`windows`。实际操作自动选择当前系统，且要求管理员权限。Unix 文件及其父目录必须由 root 持有、不可被组或其他账户改写；二进制通常为 755，配置和凭据必须仅允许所有者访问，通常为 600。Windows 使用管理员管理的目录并限制凭据读取权限。

### macOS

准备本次构建的客户端、配置和已有服务端凭据：

```bash
sudo mkdir -p /Library/Socks5Proxy
sudo install -m 755 ./socks5proxy_client_darwin_arm64 /Library/Socks5Proxy/client
sudo install -m 600 ./client.json ./client.token ./server.crt /Library/Socks5Proxy/
sudo chown -R root:wheel /Library/Socks5Proxy
sudo chmod 755 /Library/Socks5Proxy

sudo python3 scripts/client-daemon.py install \
  --binary /Library/Socks5Proxy/client --config /Library/Socks5Proxy/client.json
```

Intel Mac 替换为 `darwin_amd64`。服务定义为 `/Library/LaunchDaemons/com.shikanon.socks5proxy.client.plist`，由 launchd 监督父进程，开机启动，日志写入 `/var/log/socks5proxy-client.log`。

### Linux

需要 systemd，隧道与 DNS 的系统依赖见[部署文档](tunnel.md#前置条件)：

```bash
sudo mkdir -p /opt/socks5proxy
sudo install -m 755 ./socks5proxy_client_linux_amd64 /opt/socks5proxy/client
sudo install -m 600 ./client.json ./client.token ./server.crt /opt/socks5proxy/
sudo chown -R root:root /opt/socks5proxy
sudo chmod 755 /opt/socks5proxy

sudo python3 scripts/client-daemon.py install \
  --binary /opt/socks5proxy/client --config /opt/socks5proxy/client.json
```

ARM64 替换二进制。定义为 `/etc/systemd/system/socks5proxy-client.service`，使用 `Restart=always` 监督父进程；停止后额外运行 `-recover-network`。日志可通过 `journalctl -u socks5proxy-client.service` 查看。

### Windows

在管理员管理的 `C:\Program Files\Socks5Proxy` 放置 `client.exe`、对应架构的 `wintun.dll`、`client.json` 和凭据；配置中的相对路径基于该目录。限制普通用户的写入权限及凭据读取权限。在管理员 PowerShell 中：

```powershell
python scripts/client-daemon.py install `
  --binary 'C:\Program Files\Socks5Proxy\client.exe' `
  --config 'C:\Program Files\Socks5Proxy\client.json'
```

创建 `Socks5ProxyClient` 开机计划任务，以 SYSTEM 运行，不因电池供电停止，不设置运行时长限制；任务失败时由计划任务重试，子进程失败由父进程重启。停止/卸载会匹配二进制及配置路径，结束相关进程后显式恢复网络。

## 查看、停止与卸载

使用与安装时相同的 `--binary` 和 `--config`。macOS 示例：

```bash
sudo python3 scripts/client-daemon.py status \
  --binary /Library/Socks5Proxy/client --config /Library/Socks5Proxy/client.json
sudo python3 scripts/client-daemon.py stop \
  --binary /Library/Socks5Proxy/client --config /Library/Socks5Proxy/client.json
sudo python3 scripts/client-daemon.py start \
  --binary /Library/Socks5Proxy/client --config /Library/Socks5Proxy/client.json
sudo python3 scripts/client-daemon.py uninstall \
  --binary /Library/Socks5Proxy/client --config /Library/Socks5Proxy/client.json
```

`stop` 恢复网络并停止当前运行，保留开机启动定义；下次开机仍会启动。`uninstall` 先停止和恢复，再删除系统定义。配置和凭据文件由使用者管理。Linux 替换路径，Windows 在管理员终端使用对应路径。操作前会校验安装定义指向相同二进制和配置，避免误停另一个实例。

也可独立查看或恢复：

```bash
sudo /Library/Socks5Proxy/client -config /Library/Socks5Proxy/client.json -status
sudo /Library/Socks5Proxy/client -config /Library/Socks5Proxy/client.json -recover-network
```

状态包括 `direct`、`tunnel`、`reconnecting`、`restoring`、`error`，以及 `pid`、`updated`、可选 `last_error`、`running`。`mode` 是最后保存值，`running` 通过客户端锁判断；父进程处于重启等待时可以是 `direct` 且 `running=false`，系统服务状态另由安装器查询。

默认状态目录为 Unix `/var/run/socks5proxy`、Windows `%ProgramData%\socks5proxy`。`network-state.json` 保存网络恢复步骤，`client-status.json` 保存状态，`client.lock` / `daemon.lock` 保存 OS 锁的载体；锁文件保留不表示进程仍运行。自定义状态目录时恢复必须使用原目录。不要直接删除未完成的网络恢复日志。

## 验证范围

三种传输的 Linux 隔离双栈回退、转发故障、静默丢包、服务恢复及监督子进程崩溃已验收；桌面六种客户端目标已交叉构建。macOS/Windows 系统服务定义已检查，尚未安装本机服务或实测其系统级运行。详细命令、检查项和平台边界见[2026-11-01 验收记录](watchdog-verification-2026-11-01.md)。
