# 排障

先记录版本（Release tag 或 `git rev-parse HEAD`）、系统/架构、两端参数（删除密码/令牌）、完整错误及发生时间。确认使用的是 `proxy` 还是 `tunnel`，对应端口协议不同。

## `socket: too many open files`

旧版存在明确的回收问题：客户端连接上游失败时尚未注册本地 socket 的关闭；双向复制在单向 EOF 后等待另一端而未半关闭；慢握手与空闲连接没有超时，Accept 无并发限制且错误时立即重试。新版提前注册资源回收、支持半关闭、设置超时、限制活动会话，并对资源类 Accept 错误退避到最多每秒重试。

Linux 下先查运行进程（将 `12345` 替换为实际 PID）：

```bash
PID=12345
cat "/proc/$PID/limits"
ls "/proc/$PID/fd" | wc -l
ss -tanp
ulimit -Sn
ulimit -Hn
```

`ulimit` 只反映当前 shell；systemd 或容器启动的进程应以 `/proc/PID/limits` 为准。macOS 可用 `lsof -nP -p PID` 检查句柄和连接；Windows 可在资源监视器检查 TCP 连接及进程句柄。`TIME_WAIT` 属于内核 TCP 状态，不等同于程序仍持有一个 FD。

每个活动会话最多约占两个 socket FD，另外需预留监听、日志、DNS、运行时等开销。建议：

```text
2 × max-connections + 预留FD < 进程软限制
```

例如限制为 64 时可用 `-max-connections 16` 并至少预留 16；默认 256 会话应有明显高于 512 的软限制，例如 1024。客户端、服务端分别计算，同机运行还受系统总限制约束。其他嵌入业务会使用额外 FD，需单独预算。

先升级并下调并发/空闲预算验证回收，再按负载需要提升限制：

```bash
# 仅当前 shell 和之后启动的子进程，且不得高于硬限制
ulimit -n 1024
./client -server SERVER:18888 -passwd YOUR_VALUE -recv socks5 \
  -max-connections 128 -handshake-timeout 10s -idle-timeout 5m
```

systemd 用户应在对应服务单元中设置合适的 `LimitNOFILE` 并重新启动该服务；不要只修改交互 shell 后假定守护进程已生效。单纯增大限制不能解决旧版泄漏。并发上限是资源边界，满载时额外连接会排队或超时。

可运行仓库中的可重复检查，只对测试子进程设置低限制，不修改系统参数：

```bash
go build -o /tmp/socks5proxy-client ./cmd/client
go build -o /tmp/socks5proxy-server ./cmd/server
python3 scripts/test-proxy-resources.py \
  --client /tmp/socks5proxy-client --server /tmp/socks5proxy-server \
  --limit 64 --sessions 16 --iterations 400
```

输出包括失败拨号、超量慢握手、短连接前后 FD 计数和 SIGTERM 退出结果。Linux CI 同样运行此检查；具体实测见[验证记录](verification-readme-todos-2026-09-20.md)。

## 应用代理常见错误

| 症状 | 检查与处理 |
| --- | --- |
| `connection refused` / HTTP 502 | 检查客户端 `-server`、服务端是否监听和目标是否可达；服务器用 `ss -lntp`（Linux）或 `lsof -nP -iTCP -sTCP:LISTEN`（macOS）检查监听。SOCKS 成功响应现在只在目标连接成功后发送 |
| SOCKS 版本/认证错误，HTTP 400 | 两端 `-type` / `-passwd` 必须相同；浏览器协议必须匹配客户端 `-recv`，并连接客户端端口。HTTP 模式要求绝对 `http://` URL，HTTPS 使用 CONNECT |
| HTTP 431 | 请求行和请求头总计超过 32 KiB，检查超大 Cookie/Header；请求体不受此头部上限限制 |
| `address already in use` | 同机客户端/服务端使用不同端口；排查旧进程，勿把服务端地址指回客户端 |
| `i/o timeout`，握手中断 | 检查目标 DNS/可达性及 `-dial-timeout`、`-handshake-timeout`；默认总握手预算 10 秒 |
| 静默连接几分钟后断开 | 默认双向无流量 5 分钟回收；确有长空闲需求时增大两端 `-idle-timeout` |
| curl 能访问但不经过代理 | 清空 `NO_PROXY`：加 `--noproxy ""`；浏览器检查本地地址绕过列表及插件设置 |
| 域名无法解析 | SOCKS 使用 `socks5h://` 测试服务端解析；确认服务端 DNS 可用。普通 HTTP 和 CONNECT 的目标域名也在服务端解析 |

## 全局隧道

- TLS 失败：确认 `-transport` 两端一致、系统时间正确、`-server-name` 在证书 SAN 内、CA 正确；不要关闭证书验证。`quic` 用 UDP，`tcp` 用 TCP。
- 认证失败：客户端 ID 与服务端令牌摘要条目一致；摘要计算排除令牌文件末尾换行。避免在日志或工单粘贴令牌及摘要。
- TUN 创建失败：检查管理员/root 权限。Windows 使用匹配架构的 Wintun ZIP；Linux 检查 `/dev/net/tun`。
- DNS/联网失败：Linux 客户端检查 `resolvectl status`、`/etc/resolv.conf`；服务端检查 IPv4 forwarding、FORWARD/NAT 及出口网卡。排查后端对应 UDP/TCP 端口与 MTU。
- 异常退出后路由/DNS 残留：使用同一 `-state-dir` 重启触发恢复，详见[隧道停止与恢复](tunnel.md#停止与恢复)。当前 IPv4 与 kill switch 限制见[安全模型](security.md)。
