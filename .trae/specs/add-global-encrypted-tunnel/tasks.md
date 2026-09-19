# Tasks

- [x] Task 1: 建立隧道配置与命令入口，在保持默认代理行为不变的前提下增加 `-mode tunnel`。
  - [x] 先在 `cryptogram_test.go` 增加 `CreateSimpleCipher`、`CreateRandomCipher` 和 `CreateAuth` 的固定密码/固定字节兼容向量，锁定当前编码表和往返行为。
  - [x] 先在 `e2e_test.go` 增加分别使用 `simple` 与 `random` 的代理端到端回归用例，锁定现有客户端/服务端线协议。
  - [x] 在 `internal/tunnel/config.go` 定义客户端/服务端配置、默认 MTU 1280、`-obfs none|simple|random`、服务端 `-obfs-allow`、参数范围和模式相关校验。
  - [x] 在 `internal/tunnel/config_test.go` 覆盖缺失证书、令牌、客户端标识、非法 CIDR/MTU、代理默认模式和合法隧道配置。
  - [x] 修改 `cmd/client/main.go` 与 `cmd/server/main.go`，解析规格中的参数，根据模式分派，并用 `signal.NotifyContext` 传递取消信号；代理分支继续原样传递 `-type`、`-passwd`、`-recv`、`-local` 和 `-server`。
  - [x] 运行 `go test ./...`，预期新增模式分派测试及 `simple` / `random` 兼容回归测试全部通过。

- [x] Task 2: 实现可独立测试的 v1 控制协议和 IPv4 数据报校验。
  - [x] 在 `internal/tunnel/protocol/control.go` 定义 ALPN、协议版本、含 `obfs` 协商值的认证请求/响应/错误消息及 64 KiB 长度前缀编解码。
  - [x] 在 `internal/tunnel/protocol/datagram.go` 编解码 `version | type | raw_ipv4_packet`，在包校验前后按协商模式调用现有 `CreateAuth` 变换，并暴露源/目标地址。
  - [x] 在 `internal/tunnel/protocol/control_test.go` 覆盖分片读取、短写、超长消息、未知版本、未知类型和错误响应。
  - [x] 在 `internal/tunnel/protocol/datagram_test.go` 覆盖合法包、伪造长度、非 IPv4、空包和超 MTU 包。
  - [x] 运行 `go test ./internal/tunnel/protocol -race`，预期全部通过且无竞态。

- [x] Task 3: 实现 TLS 1.3 QUIC 传输层。
  - [x] 在 `go.mod` 和 `go.sum` 固定受维护且与项目 Go 工具链兼容的 `quic-go` 与 TUN 依赖版本；如依赖要求提高 Go 基线，同步更新 CI 和发布工具链。
  - [x] 在 `internal/tunnel/transport/quic.go` 封装客户端拨号和服务端监听，固定 ALPN、TLS 1.3、握手超时、DATAGRAM 能力检查和有界保活。
  - [x] 客户端使用系统根或 `-ca` 指定 CA，始终校验 `-server-name`；不提供跳过证书校验参数。
  - [x] 禁用 0-RTT，并将控制流限制为每连接一条；数据只允许在认证完成后收发。
  - [x] 在 `internal/tunnel/transport/quic_test.go` 使用临时 CA/证书覆盖成功握手、名称不匹配、不受信证书、ALPN 不匹配和 DATAGRAM 未协商。
  - [x] 运行 `go test ./internal/tunnel/transport -race`，预期全部通过。

- [x] Task 4: 实现令牌认证、地址池和并发会话表。
  - [x] 在 `internal/tunnel/server/auth.go` 解析 `<client_id>:<sha256-hex>` 令牌文件，拒绝重复 ID、非法摘要和权限过宽的敏感文件。
  - [x] 在 `internal/tunnel/server/pool.go` 排除保留地址并确定性预留客户端 IPv4，使服务端重启后地址稳定。
  - [x] 在 `internal/tunnel/server/sessions.go` 提供按客户端 ID 和虚拟 IPv4 的并发安全注册、查询、替换与释放。
  - [x] 在对应的 `*_test.go` 中覆盖摘要校验、并发分配唯一性、池耗尽、稳定预留和重连替换。
  - [x] 运行 `go test ./internal/tunnel/server -race`，预期全部通过。

- [x] Task 5: 建立跨平台 TUN 设备抽象。
  - [x] 在 `internal/tunnel/device/device.go` 定义包读写、名称、MTU 和关闭接口。
  - [x] 基于 `golang.zx2c4.com/wireguard/tun` 统一接入 Linux TUN、macOS utun 和 Windows Wintun，并处理批量读取。
  - [x] 完成 Linux、macOS amd64/arm64 和 Windows amd64 目标编译。

- [x] Task 6: 实现 Linux 服务端网络配置事务。
  - [x] 定义参数化系统命令执行器，生产代码不拼接 shell 命令。
  - [x] 配置 TUN 地址和链路状态，并在 `-manage-network=true` 时管理 `ip_forward`、FORWARD 与 MASQUERADE。
  - [x] 原子持久化恢复状态，退出时逆序移除自身规则并恢复由自身修改的原值。
  - [x] 使用伪执行器测试恢复顺序、状态持久化和接口名称注入防护。

- [x] Task 7: 实现 Linux 隧道服务端的数据面和生命周期。
  - [x] 完成 QUIC 接入、控制流认证、稳定地址分配、会话替换、超时和优雅关闭。
  - [x] 上行先按会话模式还原数据包，再校验源地址并写入 TUN。
  - [x] 下行按目标虚拟 IPv4 选择会话，并通过有界队列发送混淆后的数据报。
  - [x] 会话、认证、地址池和传输测试通过 race 检查。

- [x] Task 8: 实现 macOS 和 Windows 客户端 TUN 设备。
  - [x] macOS 使用系统 utun 并读取内核分配的实际接口名。
  - [x] Windows 使用稳定 GUID 的 Wintun 适配器，DLL 仅从应用目录或 System32 安全加载。
  - [x] macOS amd64/arm64 和 Windows amd64 客户端完成 `CGO_ENABLED=0` 交叉构建。

- [x] Task 9: 实现 macOS 客户端网络配置、DNS 和恢复事务。
  - [x] 原子记录跨平台网络状态、严格文件权限、版本校验和残留事务恢复。
  - [x] 读取默认网关、物理接口和 DNS，配置服务端豁免路由、两条 IPv4 默认分流路由和 IPv6 阻断。
  - [x] 使用参数化 `route`、`ifconfig` 和 `networksetup` 调用，恢复时只撤销状态文件记录的变更。
  - [x] 固定系统输出测试覆盖网络服务名、DNS 保存恢复和服务端豁免路由。

- [x] Task 10: 实现 Windows 客户端网络配置、DNS 和恢复事务。
  - [x] 通过参数化 PowerShell 获取默认路由、接口索引和 DNS，配置 TUN、豁免路由、默认分流路由及 DNS。
  - [x] 添加可识别、可恢复的 IPv6 出站阻断规则。
  - [x] 状态写入 `%ProgramData%\\socks5proxy\\`，通过 ACL 限制为管理员和 SYSTEM 可读。
  - [x] 伪执行器覆盖特殊接口名拒绝、物理 DNS 保存和恢复。
  - [x] Windows amd64 网络包和客户端完成交叉编译。

- [x] Task 11: 实现客户端连接、全局接管、故障阻断和重连。
  - [x] 按“先连接认证、后修改网络”的顺序编排 QUIC、TUN 和网络事务。
  - [x] 双向转发 TUN 与 QUIC DATAGRAM，在 TLS 内按协商模式处理负载并校验源/目标地址。
  - [x] 实现带抖动指数退避；意外断线保持 fail-closed，显式取消按逆序恢复网络。
  - [x] 服务端参数变化时安全恢复并退出，避免使用旧 TUN 地址无声丢包。
  - [x] 客户端单元测试通过 race 检查。

- [ ] Task 12: 增加端到端和系统级验证。
  - [ ] 在 `tunnel_e2e_test.go` 使用临时证书、内存 TUN 和本地 QUIC 完成双客户端 IPv4 TCP/UDP 形态包双向传递，验证会话隔离。
  - [x] 在 `scripts/test-tunnel-linux.sh` 使用 Linux network namespace、veth、TUN 和 NAT 启动真实服务端/客户端，验证 HTTP、DNS UDP、客户端退出恢复及服务端停止后的 fail-closed。
  - [x] 在 `.github/workflows/ci.yml` 增加 race 单测、darwin/windows/linux 编译矩阵和具备条件时运行的 Linux namespace 集成测试。
  - [x] 运行 `go test -race ./...`、`go vet ./...` 和 `staticcheck ./...`；本机非 Linux，namespace 脚本按设计返回 77 并交由 Linux CI 执行。

- [ ] Task 13: 更新发布物和用户文档。
  - [x] 修改 `.github/workflows/release.yml`，构建 macOS amd64/arm64 客户端、Windows amd64 客户端、Linux amd64 服务端，将官方 Wintun amd64 DLL 和许可证装入 Windows ZIP，并为所有产物生成 `SHA256SUMS`。
  - [x] 在 `docs/tunnel.md` 写明证书生成/部署、令牌摘要文件、服务端防火墙和 NAT、客户端管理员权限、完整命令、正常停止、异常恢复及排障步骤。
  - [x] 修改 `README.md`，明确 `simple` / `random` 简易加密仍受支持，区分代理混淆与 TLS 1.3 安全加密隧道，并链接隧道文档。
  - [x] 修改 `docs/release.md`，列出新增平台产物、Wintun 许可证和校验方式。
  - [ ] 使用干净目录按文档分别演练 Linux 服务端、macOS 客户端和 Windows 客户端命令，确认参数、文件名与发布物一致。

# Task Dependencies

- Task 2 depends on Task 1.
- Task 3 depends on Task 2.
- Task 4 depends on Task 2.
- Task 5 depends on Task 1.
- Task 6 depends on Task 5.
- Task 7 depends on Tasks 2, 3, 4, 5, and 6.
- Task 8 depends on Task 5.
- Tasks 9 and 10 depend on Tasks 1 and 8 and may run in parallel.
- Task 11 depends on Tasks 2, 3, 8, 9, and 10.
- Task 12 depends on Tasks 7 and 11.
- Task 13 depends on Tasks 8, 11, and 12.
