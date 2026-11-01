# 不依赖 TLS 的每日令牌表隧道

`-mode tunnel -transport tcp-table` 使用普通 TCP 承载 TUN 的 IPv4 数据包，无需 TLS 证书，也无需另行创建 32 位以上客户端令牌。服务端首次启动生成 `token-table.json`；客户端通过 SSH/SCP 等方式取得同一份表。

令牌表如何派生每日替换表、字节怎样映射与还原、日期和帧长度怎样封装，见[每日令牌表的数据映射原理](data-mapping.md)，其中包含按当前实现复算的完整数据帧示例。

这是一种学习用的字节替换加密：相同一天内相同字节映射一致，可被已知明文或统计分析还原，不提供数据完整性与重放防护。现有 `quic`、`tcp`、`tcp-plain` 继续可用。

## 令牌表与日期

- JSON 表包含 `version: 1` 和 256 个不重复的随机令牌，字符为大小写英文字母及数字。
- `-table-token-length` 控制每个令牌长度，允许 8–16 位，默认 16。
- 令牌由 `crypto/rand` 生成，文件权限为 `0600`。完整文件写完后原子发布；已有文件被直接复用，损坏文件不会被自动覆盖。
- 完整表的规范化内容参与 SHA-256/HMAC 派生。映射结合 UTC 当日零点的 Unix 时间戳，通过 Fisher–Yates 生成覆盖全部 256 个字节的双射及逆表，不使用旧 `random` 模式的密码字节求和。
- 每个 TCP 数据帧：`2 字节长度 | 8 字节 UTC 当日零点时间戳 | 替换后的隧道数据报`。数字使用网络字节序，最大帧内容为 1410 字节，TUN MTU 上限仍为 1400。
- 按每个数据包的发送日期生成映射；接收端接受 UTC 昨天、今天、明天的数据，兼容跨午夜和小幅时钟偏差。两端系统应校准时间。日期字段公开，不构成防重放机制。
- 完整令牌表还派生握手凭据，复用随机挑战及双向 HMAC 证明；线路不直接发送令牌表或长期凭据。此证明仅认证握手。

服务端默认授权的客户端 ID 是 `desktop`，可用 `-client-id` 修改。一张表对应一个客户端身份；同一 ID 的新连接会替换旧连接。需要多个身份时，使用不同服务端实例、令牌表、端口、TUN 和 CIDR。

## 服务端首次启动

Linux 需要 root、`/dev/net/tun`、`ip`、`iptables` 和 `sysctl`。先通过 `ip -4 route show default` 确认出口网卡。

```bash
sudo ./server \
  -mode tunnel -transport tcp-table \
  -local :24443 \
  -table-file /etc/socks5proxy/table/token-table.json \
  -table-token-length 16 \
  -client-id desktop \
  -tunnel-cidr 10.254.24.0/24 \
  -tun-name s5ptable0 \
  -state-dir /var/lib/socks5proxy-table \
  -outbound-interface eth0 \
  -dns 1.1.1.1 -obfs-allow none
```

启动后会生成目录和文件。无需传入 `-cert`、`-key` 或 `-token-file`。先启动服务端，再通过已经授权的 SSH 连接复制表：

```bash
scp root@SERVER:/etc/socks5proxy/table/token-table.json ./token-table.json
chmod 600 ./token-table.json
```

整个表是共享秘密，应保留其权限。服务端重启保留表，以支持现有客户端重连。轮换时先停服务端，备份并移走旧表，再启动生成新表，并同步给客户端；客户端需要重启载入新表。运行中的进程不自动读取修改后的文件。

## TUN 全局客户端

Linux 示例，`SERVER` 替换为服务端地址：

```bash
sudo ./client \
  -mode tunnel -transport tcp-table \
  -server SERVER:24443 \
  -client-id desktop \
  -table-file ./token-table.json \
  -tun-name s5ptable0 \
  -state-dir /var/run/socks5proxy-table \
  -obfs none
```

macOS/Windows 使用相同连接参数；省略 `-tun-name` 使用对应平台默认值。Windows 仍需 Wintun DLL。`tcp-table` 必须使用 `-obfs none`，每日映射已经包含在传输层。

程序创建 TUN，安装 `0.0.0.0/1`、`128.0.0.0/1` 两条路由接管全局 IPv4 流量，为外层服务器 IP 保留物理出口路由，并沿用 DNS 管理、断线重连和正常退出网络恢复。TCP、UDP、ICMP、DNS 都可通过隧道。

Linux 默认需要 systemd-resolved。使用独立网络命名空间或者外部 DNS 管理时，加 `-linux-dns=false`，并自行配置该环境的 DNS。IPv6 的现有平台限制参见[全局隧道部署](tunnel.md)。

在远程 SSH 服务器上测试客户端时，建议在独立网络命名空间安装全局路由。直接在 SSH 主机切换默认出口可能改变 SSH 回程。

## 移动端核心

Go mobile 核心配置支持 `transport: "tcp-table"`，配置 JSON 中的 `token_table` 字段直接放入令牌表对象，`obfs` 为 `none`，无需 `token` 或 `ca_pem`：

```json
{
  "server_addr": "SERVER:24443",
  "client_id": "desktop",
  "transport": "tcp-table",
  "obfs": "none",
  "token_table": {
    "version": 1,
    "tokens": []
  }
}
```

示例中的 `tokens` 必须替换为服务端生成的完整 256 项数组。原生 Android/iOS 配置界面尚未增加令牌表导入入口；核心可供应用集成使用。

## 验证

```bash
go test ./...
go test -race ./...
go vet ./...
sudo env TUNNEL_TRANSPORT=tcp-table bash scripts/test-tunnel-linux.sh
```

Linux 集成脚本不为 `tcp-table` 生成证书，验证 TCP 文件校验、ICMP、UDP/TCP DNS、UDP 大包、重启重连及路由恢复。[真实服务器测试记录](token-table-verification-2026-10-24.md)记录国内至海外的结果。
