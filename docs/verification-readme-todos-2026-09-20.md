# README TODO 验证记录（2026-09-20）

## 范围

基线为 `9e8cb8a`。本次覆盖 README 未完成的 #29（安全模型）、#2（同机部署）、#3（FD 耗尽）、#4（下载/使用说明），修改根包应用代理和 CLI，并增加 CI 资源回归。未修改 tunnel 传输协议、系统网络管理或移动原生应用。

公开 issue 状态核对：#4 已在 2026-06-07 关闭并转用 Releases；README 的复选框和使用参数仍需更新。此次只更新仓库实现与文档，不代表修改 GitHub issue 状态或已发布新版本。

## 缺陷分析与修复

| 问题 | 原因 | 修复 |
| --- | --- | --- |
| 上游不可达时 socket 留存 | `handleProxyRequest` 在 Dial 成功后才 defer 本地 Close | 会话开始立即注册关闭；失败拨号返回 EOF/HTTP 502 |
| 双向复制挂起 | 两个复制协程互相等待，没有传递正常 EOF | 正常结束 `CloseWrite`，继续排空另一方向；异常/取消关闭两端 |
| FD 无界增长、慢连接长期占用 | 无并发上限、协议/拨号/空闲超时；Accept 错误忙循环 | 接收前限流、上下文取消、超时、资源类 Accept 错误指数退避 |
| TCP 分片/粘包握手错误 | 一次 Read 被误当作完整协议帧 | 按字段长度精确读取，保留后续请求/数据 |
| NMETHODS=254/255 失败 | `2 + uint8` 算术溢出 | 转为 int 后计算长度 |
| 未提供 no-auth 仍被接受 | 默认选中 0 而非无支持方法 | 检查方法列表，拒绝时返回 `05 ff` |
| 目标连接失败仍返回成功 | 解析请求时即发送 CONNECT success | DialContext 成功后再应答；失败返回非零 SOCKS 状态 |
| HTTP 越界、截断大请求、无 CONNECT | 手工拆分一次 1024 字节 Read | 有界请求头 + `http.ReadRequest`、流式请求体、CONNECT、400/431/502 |
| `DecodeRead` 丢最后一段数据 | 忽略同时返回数据与 EOF 的 Reader；解码整个 buffer | 保留 n 和 error，只解码有效前缀；编码写入检查 short write |

域名解析纳入 DialContext 的超时和取消。导出的 `LSTRequest` 保留原先解析到 `RAWADDR` 的兼容行为；生产路径使用不立即解析 DNS 的内部解析器。

默认参数：每进程 256 活动会话、拨号 10 秒、总握手 10 秒、双向空闲 5 分钟。零值选默认，负数报错。旧 `Client` / `Server` API 保留，新增 `ClientContext` / `ServerContext` / `ProxyOptions`。

## 生成的用例

单测流程 Step1–7 完成：准备、上下文、范围、缺陷分析、生成/验证/处置、覆盖率检查、报告。Go 根包为执行单元；没有项目级额外单测约定。覆盖率门禁按规则跳过（非 flux，用户未要求门禁），不以包覆盖率代替增量覆盖率；`utree flush` 已执行成功。

修复前先落盘 `proxy_reliability_test.go` 并运行：

```bash
go test -count=1 -timeout 15s \
  -run '^(TestProtocolVersionHandleHandshake|TestHandleHandshake|TestHandleProxyRequest|TestHandleClientRequest)$' .
```

真实结果为退出码 1：10 个子用例中 3 个正常场景通过，7 个失败，稳定对应五类缺陷：方法长度溢出、不支持的方法被接受、分片/粘包误读、上游失败连接泄漏、连接前错误返回成功。没有把失败行为写成期望值。测试生成阶段保留失败作为证据；在后续开发修复阶段，这些断言原样通过。

新增/维护测试包含：

- `proxy_reliability_test.go`：上述五类缺陷，以及无效协议输入。
- `proxy_runtime_test.go`：并发容量及复用、取消 Accept/Read、EMFILE/ENFILE 退避与永久错误返回、半关闭排空、读错误/空闲/取消收敛、单向流量延长双向 deadline、慢握手超时、选项校验。
- `e2e_test.go`：随机端口且可关闭的本地链路；simple/random SOCKS5 转发、336000 字节 POST（固定长度与分块）、Expect: 100-continue、代理专用头移除、HTTPS CONNECT、非法请求/超大头/无效端口、目标拒绝时 HTTP 502、CONNECT 粘包及半关闭。
- `server_test.go`：保留读写错误和分片域名场景，fixture 改用真实 Reader 语义；解析阶段不再期待成功应答。

## 验证结果

macOS arm64，Go 1.26.0，staticcheck 2026.1：

```bash
go test -race -timeout 90s ./...
go vet ./...
staticcheck ./...
bash scripts/build-desktop.sh
git diff --check
```

全部通过。Linux x86_64 上的 `go test -race -timeout 90s ./...` 也通过。桌面构建覆盖 macOS/Linux/Windows 客户端 amd64、arm64，以及 Linux/Windows 服务端 amd64、arm64（共 10 个目标）。全仓测试包含既有 tunnel 和 mobile Go 包；不据此宣称 Windows、Android、iOS 真机联网验收。

Linux x86_64 的独立临时目录中，用真实客户端/服务端二进制运行 `scripts/test-proxy-resources.py`。仅测试子进程的 RLIMIT_NOFILE 被设为 64，未更改系统限制、路由或既有代理服务。新版本设置 16 活动会话、拨号/握手/空闲 300ms。

| 场景 | 修复前（基线） | 修复后 |
| --- | --- | --- |
| 48 个上游失败连接，保留对端 socket | FD 8 → 56，未回收，检查按预期失败 | FD 7 → 7，本地读取 EOF |
| 再执行 400 次失败拨号 | 旧版在前一项失败后停止 | 完成后 FD 7 |
| 48 个未完成握手连接 | 未在旧版继续执行 | 客户端/服务端峰值 39/23，恢复到 7/7 |
| 16 并发、400 次粘包请求 + 半关闭响应 | 未在旧版继续执行 | 全部成功，结束后 FD 7/7 |
| 活动连接期间 SIGTERM | 未在旧版验证 | 两进程 3 秒内退出，退出码 0 |

第一轮 Linux 短连接检查暴露测试目标 Python TCPServer 默认 backlog=5 小于 16 并发，造成目标拨号超时。将测试目标 backlog 改为 128 后重新执行全部场景通过；没有放宽代理断言或超时来掩盖失败。

CI 增加相同的低 FD 检查，未来变更继续覆盖回收行为。日志计数是该环境的一次实测，不是所有平台的固定 FD 开销或性能上限。

## 文档与兼容边界

- `docs/security.md`：混淆至多 256 张表、监听认证、出口信任/ACL、TLS 与明文模式、IPv4/kill switch 边界。
- `docs/proxy.md`：同机双端口、curl/浏览器协议匹配、HTTP CONNECT、默认参数、取消 API。
- `docs/troubleshooting.md`：FD 预算与进程限制、可重复检查、常见连接/HTTP/DNS/TLS/TUN 问题。
- `docs/release.md`：真实 Releases 入口、系统/架构选择、单资产校验、源码和移动构建入口。

客户端 CLI 默认监听改为 `127.0.0.1:8888`；需要其他机器访问时必须显式设置 `-local`。普通 HTTP 每条本地连接处理一次请求并关闭；请求头上限 32 KiB，主体流式转发。静默连接会受新增空闲超时约束，长空闲应用应配置更大预算。应用代理混淆仍不提供密码学安全性。
