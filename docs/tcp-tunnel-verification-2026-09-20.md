# TCP 全局隧道实现与验证（2026-09-20）

## 交付范围

保留默认 QUIC，新增 `-transport tcp`（TLS 1.3）及显式 `-transport tcp-plain`。两种 TCP 使用相同的挑战认证、IP 封包、混淆、TUN 和网络恢复逻辑。`random` 是字节替换混淆，不提供安全加密。

客户端和服务端都增加对应参数；TCP+TLS 严格验证证书及 ALPN，不会自动降级。TCP 明文模式不直接传送令牌或摘要，但没有后续数据包机密性和完整性；性能实验使用独立临时令牌。QUIC 继续使用原线协议。

认证读写加入 10 秒截止时间及取消关闭。TCP 每 15 秒发送心跳，接收空闲 45 秒及写入超过 10 秒时关闭重连；旧 relay 线程退出后才使用新连接。

此外复用 TUN 的批量读缓冲区，避免每次原生读操作重新分配整批最大 IP 缓冲区。向传输线程返回的包仍各自持有内存，不引用可被后续读取覆盖的工作区。这项优化同时用于 QUIC 和 TCP。

## 测试环境与边界

- 构建和测试主机：`106.13.216.217`，Linux amd64，Go 1.26.0。
- 测试源码目录：`/root/socks5proxy-tcp-test`（复用缓冲区前）、`/root/socks5proxy-tcp-v2`（最终实现）。
- 功能与性能测试使用三个 Linux network namespace，经 veth 连接；外层 MTU 1228，没有人为注入丢包。宿主默认路由、DNS 和正式服务配置不参与这些测试。
- 性能对照固定 `random`、TUN MTU 1150、确定性不可压缩文件；下载核对完整长度及 SHA-256，上传核对服务端收到内容的 SHA-256。
- 每种 TCP 三轮交替测试；第二轮反转顺序。每轮含 1 MiB 下载、8 MiB 下载和 8 MiB 上传。记录 curl 指标、退出码、哈希校验和两端隧道进程 CPU 秒。
- **本报告的 namespace 性能不能视为两台公网服务器之间的测速。** 服务端 `101.47.18.93` 的旧 SSH 复用失效，现有本机 RSA/Ed25519 及客户端 RSA 均被服务端拒绝，尚未恢复登录。没有执行该机的新版本部署或新的公网 TLS/明文/QUIC 对照。

## 单元测试

按 bits-unit-test-gen 的准备、上下文、范围、缺陷分析、生成验证、覆盖率门禁和报告流程执行。范围后来扩展到 TUN 缓冲区复用，并先补充范围分析，再生成测试。

- 新增 17 个顶层测试，80 个叶子场景，全部通过；历史测试也全部通过。
- 范围：配置枚举及兼容默认值、HMAC/nonce/响应参数绑定、凭据不上线、TCP 封包与短 I/O、心跳与并发写、TLS 校验、控制到数据模式切换、阻塞 I/O 取消、会话替换、IP 地址校验、relay 退出等待、TUN 工作区复用及返回包独立性。
- 生成→验证第一轮：protocol、transport、config、server、client 各包通过。增加 relay 与 transport 生命周期场景后再验证通过；增加 TUN 场景后 device 包通过。
- 全套验证：`go test -json -count=1 -timeout=90s ./...`、`go vet ./...`、`go test -race -count=1 -timeout=90s ./...` 均退出 0。
- 无项目或用户指定覆盖率门槛，且非 flux 运行；按技能规则跳过覆盖率统计，不用包级覆盖率替代增量指标。
- `utree flush` 已执行成功。完整命令输出保存在本地 `/tmp/s5-tcp-results/`。

### 修复的历史缺陷

| 问题 | 基线复现 | 最终结果 |
| --- | --- | --- |
| 客户端 QUIC 认证读取不响应 context 取消（P1） | `949ff7e` 上 `TestConnectCancelsStalledAuthentication` 连续 3 次失败，300 ms 仍未退出 | 同一正确行为断言通过；加入认证截止时间及取消关闭 |
| 服务端控制流接受后，部分认证头可以无限阻塞（P1） | `949ff7e` 上 `TestHandleConnectionCancelsPartialAuthentication` 连续 3 次失败，取消后 300 ms 仍未退出 | 同一正确行为断言通过；认证预算覆盖完整交换 |

基线测试仅在独立源码目录进行，失败记录保留于 `auth-baseline.log`。没有通过放宽断言或删除用例掩盖失败。

### 额外检查

首次下载 staticcheck 因 `proxy.golang.org` 访问超时失败；切换本次命令的 Go 模块代理后工具安装成功。全仓 staticcheck 报告两处基线问题：`internal/tunnel/network/client.go:243,256` 的 ST1005（错误文案首字母大写）。本次变更包（tunnel、protocol、transport、client、server、device、cmd）单独检查通过。

全仓格式检查也存在基线文件 `internal/tunnel/network/client_test.go` 的格式差异。本次新增及修改 Go 文件已格式化；未修改该无关历史测试。

## 集成测试

`scripts/test-tunnel-linux.sh` 支持 `TUNNEL_TRANSPORT`、`TUNNEL_OBFS`；默认仍为 QUIC/random。三种传输 × 三种混淆均验证：

- 直接路径不可达，开启隧道后 HTTP 可达；1 MiB 下载完整且 SHA-256 相同。
- 满 TUN MTU 的 DF ICMP；UDP 与 TCP DNS。
- 1、512、1122、4096 字节 UDP 回显，含 IPv4 分片与重组。
- 服务端停止后不回落直连，服务端网络状态及自有防火墙规则恢复。
- 服务端重启后原客户端重连，再次完整下载并校验。
- 客户端退出，路由与启用前快照逐字相同；namespace、进程和临时凭据清理。

功能矩阵用客户端/服务端配置 MTU 1280：QUIC 按原策略限制到 1150，TCP 实际支持 1280。性能测试单独统一为 1150。

## 性能记录与解释

最终 24 次文件传输全部成功、长度及 SHA-256 正确。结果为隧道建立后的传输墙钟时间，不包含隧道认证时间；TCP 两种模式取三轮中位数，QUIC/传统 SOCKS5 为单轮参照。本任务没有同时运行其他测试、构建或下载工具；没有人为停止主机上既有的其他业务。

| 后端（均 random） | 1 MiB 下载 | 8 MiB 下载 | 8 MiB 上传 | 8 MiB 下载进程 CPU 秒 |
| --- | ---: | ---: | ---: | ---: |
| TCP + TLS 1.3，n=3 | 0.050584 s | 0.247757 s | 0.277092 s | 0.390 |
| TCP 无 TLS，n=3 | 0.050787 s | 0.248623 s | 0.255934 s | 0.380 |
| QUIC + TLS 1.3，n=1 | 0.052931 s | 0.510203 s | 0.265667 s | 0.470 |
| 传统 SOCKS5/random，n=1 | 0.023833 s | 0.172506 s | 0.162998 s | 0.150 |

两个 TCP 后端的下载中位数相差不到 1%；明文上传中位数约低 7.6%，但逐轮有反转，且三轮样本不足以证明稳定优势。当前证据支持优先使用 `tcp` 保留 TLS，`tcp-plain` 作为显式实验选项。传统 SOCKS5 不执行 TUN/NAT 的全局 IP 工作，不能把其速度直接当成完整隧道替代方案的收益。

公共 TUN 工作区复用的收益更大：修复前同机 8 MiB 下载消耗两端进程约 26–31 CPU 秒，最终约 0.38–0.39 CPU 秒。旧墙钟样本受并发工具构建影响，不能据此精确计算倍速；CPU 秒和完整校验后的最终测量表明大批缓冲区重复分配已被消除。这个结论不说明公网 UDP 丢包已经解决。

逐条样本：[CSV](./tcp-tunnel-benchmark-2026-09-20.csv)。完整 curl JSON 保存在本地 `/tmp/s5-tcp-results/namespace-bench-final.jsonl` 和测试主机 `/root/s5-tcp-build/namespace-bench-final.jsonl`。执行方法：

```bash
TUNNEL_TRANSPORT=tcp TUNNEL_OBFS=random TUNNEL_TEST_MTU=1150 \
  TUNNEL_BENCH_ROUND=1 TUNNEL_BENCH_OUTPUT=/tmp/tunnel-bench.jsonl \
  bash scripts/test-tunnel-linux.sh
```

将 `tcp` 换为 `tcp-plain` 测无 TLS；`quic` 测原后端；`proxy` 运行传统 SOCKS5/random 对照，后者没有 TUN，不能承载完整系统 IP 流量。

`scripts/benchmark-tunnel.py` 提供固定文件 HTTP 服务、上传哈希验证和有界测量。最终上传明确禁用 curl 的 `Expect: 100-continue` 等待，避免测试 HTTP 服务造成固定约 1 秒延迟。旧样本仍保留，不能与修正后上传耗时混算。

### 保留的中间结果

- 第一次重连测试对 1 MiB 下载错误地复用了“等待连通”的 3 秒预算，QUIC 出现多次部分下载超时。随后改为小请求确认重连，再按与首轮相同的 20 秒预算完整下载；未减少文件或省略哈希检查。
- 复用 TUN 工作区前，TCP 8 MiB 下载需要十几至几十秒，两端进程 CPU 约数十秒。原始 18 条测量均保留于 `namespace-bench.jsonl`，期间有测试/工具构建并发，不用其墙钟时间作为严格 TLS 开销比较。
- 复用后首轮测量保留于 `namespace-bench-optimized.jsonl`，其上传仍含上述 `100-continue` 固定等待。
- `optimized-performance.log` 中传统代理完成测量后，清理曾因后台代理进程忽略 SIGINT 停住；确认具体测试 PID 后用 SIGTERM 结束。脚本已对代理模式改用 SIGTERM；正式隧道仍正常处理 SIGINT 恢复网络。
- 初版精确路由快照检查在 veth 对端未启动时保存了带 `linkdown` 的路由，退出时链路已启用，产生两次测试失败。差异只有该标记；快照移到全部链路就绪后、隧道启动前再取，仍要求逐字相等。复现输出保留于 `route-snapshot-check.log`。

## 构建产物

最终版本使用 `CGO_ENABLED=0 go build -trimpath` 编译，存于客户端主机 `/root/s5-tcp-build/final/`，未安装到正式服务路径。
本机副本位于 `/tmp/s5-tcp-dist/`，已逐一验证相同 SHA-256。Windows 产物使用前重命名为 `.exe`。

| 产物 | SHA-256 |
| --- | --- |
| client-linux-amd64 | `8c506d6d53c5035fda7fedfd34a3bdf490ab865eee975ad51b9fce5fc5054cfd` |
| server-linux-amd64 | `119dba6d58fe9c64248bae4bacd506fe81f280e9b3f00e3360e20517984c1689` |
| client-darwin-amd64 | `2c7d955fa21c07676f3b3b780965134fcda7ab3e63b7a65d1c8df4c4e42cc262` |
| client-darwin-arm64 | `3e5c54a4ac9c9089057e1491763f1783fb2bb91a2b40918b3e33782bdb9f916c` |
| client-windows-amd64 | `d29d048e0422e81d647899241b6ff2c8b4d301b5c5c16cfff26e8d4089e51115` |

## 公网实测、部署及恢复状态

本次没有改动服务端生产 QUIC、TCP 443 的其他业务，也未部署未经公网验证的版本。客户端正式服务保持停止；本轮实验仅运行于 namespace。服务端正式 QUIC 之前最后确认是 active/enabled；由于当前 SSH 登录被拒绝，本轮无法重新确认其运行状态。

最终客户端 `ActiveState=inactive`、`SubState=dead`、`UnitFileState=disabled`；无遗留测试 namespace 或 TUN，物理默认路由仍为 `172.16.16.1 dev eth0`。全部 namespace 临时认证文件、服务及链路由清理过程删除，额外临时 SSH known-hosts 文件已移除。本次未替换正式二进制，因而没有远端服务变更需要回滚。

待恢复 `101.47.18.93` SSH 登录后，可使用独立高端口、TUN、CIDR、状态目录及临时令牌进行同条件公网复测。多实例的 `ip_forward`/NAT 由统一网络配置管理，实例使用 `-manage-network=false`，避免多个管理器交错恢复共享状态。

尚待完成：公网三轮 TLS/明文对照、QUIC 和 SOCKS5 基线、Google/YouTube HTTPS、真实线路 DNS/ICMP/UDP 与重连，以及最终服务部署。现有 UDP 线路丢包结论没有被本轮本机测量推翻或证明已修复。
