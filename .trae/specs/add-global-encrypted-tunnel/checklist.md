# 验收清单

## 兼容性与配置

- [x] 不传 `-mode` 时，现有客户端和服务端仍按 `proxy` 模式运行，HTTP/SOCKS5 行为与参数保持兼容。
- [x] `CreateSimpleCipher`、`CreateRandomCipher`、`CreateAuth` 及其现有接口、密钥派生/替换表算法和固定兼容向量保持不变。
- [x] 代理客户端和服务端分别使用 `-type simple` 与 `-type random` 时，都能通过现有线协议完成端到端转发。
- [x] 代理模式继续接受并原样处理 `-type`、`-passwd`、`-recv`、`-local` 和 `-server`，未删除或重命名现有参数。
- [x] `tunnel` 模式在任何系统网络修改前拒绝缺失或非法的服务端地址、客户端 ID、令牌、证书、CIDR、DNS 和 MTU 配置。
- [x] `proxy` 模式不会创建 TUN/Wintun、建立 QUIC 连接或修改路由/DNS。

## 加密与认证

- [x] 隧道控制消息和 IP 包只通过 TLS 1.3 QUIC 传输，不存在使用 `simple` / `random` 替代 TLS 或明文回退的路径。
- [x] 隧道 `-obfs` 支持 `none`、`simple`、`random` 且默认 `none`；服务端可通过允许列表拒绝模式，不能静默降级。
- [x] 启用 `simple` / `random` 时只处理 QUIC DATAGRAM 的 IP 包负载，服务端在校验前还原，控制和认证消息不参与混淆。
- [x] 客户端验证证书信任链、有效期和服务器名称；无跳过验证的命令参数。
- [x] ALPN 固定为 `socks5proxy-tunnel/1`，QUIC DATAGRAM 未协商时连接失败。
- [x] 0-RTT 未启用，认证前不能发送隧道数据。
- [x] 合法客户端能认证并获得唯一虚拟 IPv4 地址；非法 ID 与非法令牌得到相同的通用失败响应。
- [x] 服务端令牌比较使用摘要和常量时间比较，日志、错误和状态文件均不包含令牌原文、私钥或 IP 包负载。

## 协议与数据面

- [x] 控制消息支持分片读取和短写，拒绝超过 64 KiB、未知版本或未知类型的消息。
- [x] 一个完整 IPv4 包对应一个 QUIC DATAGRAM，双方拒绝非 IPv4、长度不一致、错误版本和超过协商 MTU 的包。
- [x] 服务端拒绝源地址不等于会话获配地址的客户端包。
- [x] 服务端能将返回包按目标虚拟 IPv4 只发送给对应在线会话。
- [x] 地址池并发分配不重复，耗尽时只拒绝新会话，同一客户端重连会替换旧会话并复用地址。
- [x] 单客户端队列拥塞不会阻塞其他会话，并有可观察的丢包计数。

## macOS 客户端

- [x] macOS amd64 和 arm64 客户端可在 `CGO_ENABLED=0` 下构建。
- [ ] 客户端以管理员权限创建 `utun`，使用内核返回的实际接口名并配置获配地址和 MTU。
- [ ] 客户端先固定服务端 IP 并安装物理网关 `/32` 豁免路由，再安装隧道默认路由，不发生路由递归。
- [ ] 系统 DNS 被切换为隧道 DNS，DNS 请求经 TUN；非链路本地 IPv6 在 v1 运行期间被阻断。
- [ ] 网络服务名称含空格、多个默认路由和服务端使用域名时仍能正确应用与恢复配置。
- [ ] 启动中途失败、正常退出和发现残留状态文件时，原路由、DNS 与 IPv6 状态均可恢复。

## Windows 客户端

- [x] Windows amd64 客户端可在 `CGO_ENABLED=0` 下构建，发布流程包含匹配架构的官方签名 Wintun DLL 和许可证。
- [ ] 客户端以管理员权限创建稳定 GUID 的 Wintun 适配器，并配置获配地址、MTU、路由和 DNS。
- [ ] 客户端为服务端 IP 安装原接口 `/32` 豁免路由，并用 TUN 接管默认 IPv4 流量。
- [ ] 非链路本地 IPv6 在 v1 运行期间被可恢复地阻断。
- [ ] 接口名称含特殊字符、多个默认网关、适配器提前消失和部分状态缺失时，配置与恢复逻辑不发生命令注入且保持幂等。
- [x] `%ProgramData%\\socks5proxy\\` 中的事务状态通过 ACL 限制为管理员和 SYSTEM 可读。

## 断线与恢复

- [x] TLS/令牌认证成功之前，客户端不会创建 TUN 或修改系统网络。
- [x] TUN、路由或 DNS 任一步骤失败时，已完成步骤会按逆序回滚。
- [x] 隧道意外断开后路由保持 fail-closed，业务流量不会回落到物理默认路由，客户端按带抖动指数退避重连。
- [x] SIGINT、SIGTERM 和 Windows 控制台中断会停止收发、恢复网络并删除已完成事务状态文件。
- [x] 异常退出后再次启动会先恢复残留事务，再建立新隧道。

## Linux 服务端

- [ ] Linux 服务端创建并配置 TUN，能够承载多个已认证客户端。
- [x] `-manage-network=true` 只为隧道 CIDR 和指定出口网卡启用所需的 IPv4 转发、FORWARD 和 MASQUERADE。
- [x] 服务端退出或启动失败时只删除自身带唯一标识的防火墙规则，并正确恢复由自身修改的 `ip_forward` 原值。
- [x] `-manage-network=false` 不修改 sysctl 或防火墙。
- [x] 网卡名和其他外部配置通过参数传递，不经过 shell 字符串拼接。

## 测试、发布与文档

- [x] `go test -race ./...`、`go vet ./...`、`staticcheck ./...` 和格式化检查通过。
- [x] CI 配置 Linux、macOS amd64/arm64 和 Windows amd64 的目标编译检查，本机交叉编译通过。
- [ ] 本地 QUIC 端到端测试覆盖 TCP/UDP 形态包、DNS 形态包、双客户端隔离、伪造源地址和重连。
- [ ] Linux network namespace 测试验证真实 TUN、HTTP、UDP、DNS、NAT、fail-closed 和退出恢复。
- [ ] Release 包含规定的 macOS、Windows 和 Linux 产物及统一 `SHA256SUMS`。
- [x] `README.md`、`docs/tunnel.md` 和 `docs/release.md` 清楚区分代理混淆与 TLS 1.3 加密隧道，并提供可复现的部署、启动、停止、恢复和排障步骤。
