# TCP 默认 BBR 与作用范围

Linux 桌面/服务端上的程序数据 TCP socket 默认尝试 `bbr`。实现位于 `internal/tcpopts/`，调用范围：

- 应用代理服务端接受的客户端 TCP 连接；
- 应用代理拨出的远程/目标 TCP 连接；
- `tcp`、`tcp-plain`、`tcp-table` 隧道的外层拨出和接受连接。

在转发或协议握手之前调用 `setsockopt(TCP_CONGESTION)`，并 `getsockopt` 读回算法。没有修改 `net.ipv4.tcp_congestion_control`、加载内核模块、改路由或重启其他业务。BBR 是发送端算法，一端选择不强迫另一端切换。

内核未提供 BBR、没有权限或读回失败时，记录有限次数的诊断并保留原 socket 算法，不使应用连接失败。macOS、Windows、Android 保持平台算法；QUIC/UDP 不受此 Linux TCP 选项影响。QUIC 仍为隧道的默认传输，新增 BBR 默认不把 QUIC 自动改成 TCP。

## 进程级恢复

```bash
# 使用内核默认算法，不由程序切换
SOCKS5PROXY_TCP_CONGESTION=system ./socks5proxy_server_linux_amd64 ...

# 显式使用CUBIC
SOCKS5PROXY_TCP_CONGESTION=cubic ./socks5proxy_server_linux_amd64 ...
```

环境变量作用于该进程后续创建的数据连接，不是系统全局配置。已有连接不因环境变量改变而切换。非法值记录错误并保留现有算法。无参数/空值默认尝试 BBR。

## 验证边界

`go test ./internal/tcpopts` 包含真实 Linux TCP socket 的默认选择、CUBIC覆盖、system保留、非法值/关闭socket及数据传输校验，并核对全局算法未改变；没有BBR的测试内核验证兼容保留，不假装已选择BBR。

参数默认是用户选择，不构成长带宽或稳定提速承诺。发布代码不自动替换既有部署二进制；生产网关已经独立使用BBR的连接也不会因仓库提交被重启。
