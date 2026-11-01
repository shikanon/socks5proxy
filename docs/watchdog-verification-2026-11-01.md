# 桌面自动直连与守护进程验收（2026-11-01）

目标是远端隧道不可用时恢复普通网络。默认 `direct / 10s / 2s / 5s`，分别表示断线策略、回退期限、检查间隔和直连重试间隔。启用 `-daemon` 后独立父进程负责子进程崩溃恢复；后台与开机启动由系统服务定义提供。使用与配置见[守护进程说明](watchdog.md)。

## 实现与判定

- 建立连接后先认证、再通过数据连接发送 IPv4 DNS A 探测；双栈还发送 IPv6 DNS AAAA 探测，全部成功后才创建客户端 TUN、安装路由和 DNS。
- 探测经过服务端 TUN、转发/NAT 和隧道 DNS。域名默认 `example.com`，可用 `health_dns_name` / `-health-dns-name` 设置；采用实际配置的 `dns` / `dns6`。
- DNS 响应要求匹配地址、UDP 端口、随机事务 ID 和问题，校验包长度及校验和，并有成功的相应地址记录，允许 CNAME。错误、空答案、截断、过期或重复响应不能刷新健康时间。
- 新服务端另行协商带随机 nonce 的 ping/pong。有效心跳不能掩盖转发故障；旧服务端无该能力时仍执行 IP DNS 探测。
- 每个启用地址族独立计时。到期后开始恢复，不再增加一轮断线宽限；撤销路由、DNS 和自身 IPv6 阻断设置，关闭 TUN、丢弃旧队列，再进入 `direct`。
- 恢复日志记录每步撤销结果，中间步骤失败不会因其他步骤成功而丢失；恢复失败继续报告 `error`，重试成功前不接管流量。
- 父进程与子进程分别持有 OS 文件锁。子进程死亡后父进程先恢复日志，再启动替代进程；停止时有退出等待和强制结束预算。

## Go 与命令行检查

macOS ARM64 与 Linux AMD64 分别通过：

```bash
go test -race ./...
go vet ./...
```

macOS 另通过 `staticcheck ./...`。针对新增数据探测、真实 TCP 重试与取消的竞态测试重复十次通过：

```bash
go test -race -run 'TestTCPProbe|TestLiveHeartbeat|TestProbeCancellation' \
  -count=10 ./internal/tunnel/client
```

有意义的故障覆盖：

| 检查 | 结果 |
| --- | --- |
| 服务静默、错误 nonce、阻塞发送、取消时释放发送线程 | 通过 |
| 有效控制 pong 持续到达，但数据路径静默 | 探测及运行期均到期失败 |
| IPv4 正常、IPv6 静默 | 双栈不会误报可用 |
| 旧服务端无控制心跳，IP DNS 正常 | 探测及运行期均成功 |
| IPv4/IPv6 UDP 伪首部与校验和、错误地址/端口/ID/问题 | 通过 |
| SERVFAIL、空答案、截断、无关答案、过期、重复响应 | 不刷新健康时间 |
| 真实 TCP + TLS 首次 DNS 探测被丢弃 | 重试成功，随后仍可收发同一连接 |
| 首次无法连接、短暂重连、回退、地址参数变化、恢复失败重试 | 通过 |
| 父进程恢复、停止、恢复失败阻止启动；客户端锁竞争 | 通过 |
| 中间撤销失败后重载恢复日志 | 只重试失败步骤 |

CLI 冒烟使用本次构建的 macOS ARM64 客户端、临时状态目录和 `127.0.0.1:1`，通过配置覆盖、相对凭据路径、直连启动、状态查询、独占锁与主动恢复。该检查没有创建 TUN 或修改宿主网络。

Linux 全量竞态检查曾发现已有移动端包往返测试的统计时序问题：对端收到 TCP 包时，发送方统计可能尚未更新。测试改为等待两个工作线程完成统计；移动端实现与原生 VPN 生命周期没有改变。

## Linux 隔离验收

脚本为 `scripts/test-tunnel-linux.sh`，仅在远端 Linux 的临时 namespace 中运行。测试使用三个 namespace 和两组 veth，服务端 DNS 目标为隔离服务 `198.51.100.2` / `2001:db8:2::2`，无需依赖外部 DNS。测试顺序运行，避免临时接口名称冲突。

```bash
sudo env "PATH=$PATH" TUNNEL_TRANSPORT=quic \
  TUNNEL_IPV6=true TUNNEL_WATCHDOG=true ./scripts/test-tunnel-linux.sh
sudo env "PATH=$PATH" TUNNEL_TRANSPORT=tcp \
  TUNNEL_IPV6=true TUNNEL_WATCHDOG=true ./scripts/test-tunnel-linux.sh
sudo env "PATH=$PATH" TUNNEL_TRANSPORT=tcp-table \
  TUNNEL_IPV6=true TUNNEL_WATCHDOG=true ./scripts/test-tunnel-linux.sh
sudo env "PATH=$PATH" TUNNEL_TRANSPORT=quic TUNNEL_IPV6=true \
  TUNNEL_ENDPOINT_IPV6=true TUNNEL_WATCHDOG=true ./scripts/test-tunnel-linux.sh
sudo env "PATH=$PATH" TUNNEL_TRANSPORT=quic \
  TUNNEL_WATCHDOG=true ./scripts/test-tunnel-linux.sh
sudo env "PATH=$PATH" TUNNEL_TRANSPORT=quic \
  TUNNEL_IPV6=true ./scripts/test-tunnel-linux.sh
```

| 传输 | 内层 | 外层端点 | 策略 | 结果 |
| --- | --- | --- | --- | --- |
| QUIC + random | IPv4 + IPv6 | IPv4 | direct + daemon | 通过 |
| TCP + TLS + random | IPv4 + IPv6 | IPv4 | direct + daemon | 通过 |
| TCP table | IPv4 + IPv6 | IPv4 | direct + daemon | 通过 |
| QUIC + random | IPv4 + IPv6 | IPv6 | direct + daemon | 通过 |
| QUIC + random | IPv4 | IPv4 | direct + daemon | 通过 |
| QUIC + random | IPv4 + IPv6 | IPv4 | block | 通过 |

`direct` 用例将预算设为 `3s / 500ms / 500ms`，覆盖：

1. 隧道连接时验证 IPv4/IPv6 的 1 MiB 文件哈希、ICMP、UDP/TCP DNS、UDP 回显与较大 UDP 包。
2. 只在服务端 FORWARD 丢弃隧道来源前缀，保留控制连接、心跳和物理转发；要求回退期限内恢复直连。
3. 恢复后比对两种地址族原始路由快照、确认恢复日志消失，并用原物理出口下载相同文件。
4. 保持转发故障七秒，跨过多个认证/探测尝试，持续确认未创建网络恢复日志、未重新接管路由；取消 DROP 后恢复隧道与文件下载。
5. 在服务端 INPUT 静默丢弃隧道端口，模拟没有 FIN 的远端失联；恢复普通出口，解除后重新建立隧道。
6. 隧道运行时 `SIGKILL` 子进程，并保持远端失联；父进程存活、恢复原路由，随后新 PID 的子进程成功连接。
7. 服务端正常停止/重启，客户端自动直连/恢复；正常退出后核对客户端路由及服务端防火墙、IPv4/IPv6 forwarding、出口 IPv6 accept_ra 快照。

`block` 回归显式选择该策略，要求服务端断开期间保留隧道路由、隔离目标不可通过物理出口到达，恢复服务后无需重启客户端。CI 增加三传输守护矩阵及系统服务定义检查。

最终独立检查确认五份守护日志均包含转发故障、稳定直连、静默失联和子进程崩溃恢复成功记录，第六份阻断回归通过。临时 namespace、veth 和测试客户端/服务端全部退出；宿主 IPv4 默认路由与验收前一致，宿主仍无 IPv6 默认路由。

## 桌面构建与系统服务

以下构建通过，共十个二进制：

```bash
OUTPUT_DIR=/tmp/s5p-watchdog-desktop VERSION=watchdog-worktree \
  bash scripts/build-desktop.sh
python3 scripts/test-client-daemon.py
```

- 客户端：macOS、Linux、Windows，各 AMD64 / ARM64，共六个目标。
- 服务端：Linux、Windows，各 AMD64 / ARM64，共四个目标。
- Python 服务定义测试三项通过：launchd plist、systemd 路径转义和停止恢复、Windows SYSTEM 启动任务及参数引用。
- 生成的 Linux unit 用 `systemd-analyze verify` 实际检查过，修正了 `WorkingDirectory` 不接受引号的问题；未安装或启动宿主系统服务。

## 范围与边界

此验收证明隧道 DNS 与相应 IP 转发路径的代表性连通性，不能保证每个目的地址、端口或网站都可达。默认域名须有 A 记录，双栈还须有 AAAA；内部 DNS 部署可以配置相应稳定域名。

期限是开始恢复的时间，系统网络命令有额外执行时间，单轮恢复预算为十五秒。直连需要原物理网络自身可用；中断的既有 TCP 会话需要应用重试。

真实 TUN 与崩溃恢复运行验收在 Linux namespace 中完成。macOS 全量测试与跨平台构建、服务定义检查通过；没有实测 macOS/Windows 系统后台服务、睡眠唤醒或 Windows Wintun 崩溃恢复。没有安装本机守护服务、改变 AI coding 所在宿主的默认路由、部署生产服务或生成新版本发布资产。`proxy` / PAC 与 Android/iOS 原生 VPN 不纳入此桌面回退策略。
