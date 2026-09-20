# 应用代理与同机部署

proxy 模式转发 TCP 应用流量。它支持 SOCKS5 CONNECT、HTTP 普通请求和 HTTP CONNECT（包括 HTTPS 隧道）；不支持 SOCKS BIND、UDP ASSOCIATE，也不创建系统 TUN。

## 同机运行

从仓库根目录构建（也可以使用[下载的桌面二进制](release.md)替换命令名）：

```bash
go build -o server ./cmd/server
go build -o client ./cmd/client
```

终端 1 启动服务端：

```bash
./server -mode proxy -local 127.0.0.1:18888 -passwd demo-only -type random
```

终端 2 启动客户端：

```bash
./client -mode proxy -local 127.0.0.1:8888 \
  -server 127.0.0.1:18888 -passwd demo-only -type random -recv http
```

数据流为：应用 → `127.0.0.1:8888`（HTTP/SOCKS 明文入口）→ `127.0.0.1:18888`（混淆协议入口）→ 目标站点。两个端口不能相同；客户端 `-server` 指向服务端，浏览器指向客户端。目标 URL 不得指回这两个监听地址，否则会产生递归连接。

测试 HTTP 和 HTTPS：

```bash
curl --noproxy "" --proxy http://127.0.0.1:8888 http://example.com/
curl --noproxy "" --proxy http://127.0.0.1:8888 https://example.com/
```

`--noproxy ""` 清空 curl 的代理绕过规则，避免环境中的 `NO_PROXY` 让测试绕开代理。也可以在第三个终端运行 `python3 -m http.server 18080 --bind 127.0.0.1`，把测试目标改为 `http://127.0.0.1:18080/`，无需外网。

## SOCKS5 与浏览器设置

停止客户端后将 `-recv http` 改为 `-recv socks5`：

```bash
./client -local 127.0.0.1:8888 -server 127.0.0.1:18888 \
  -passwd demo-only -type random -recv socks5
curl --noproxy "" --proxy socks5h://127.0.0.1:8888 https://example.com/
```

`socks5h` 将目标域名交给服务端解析；`socks5` 的 curl 用法可能在本机解析域名。

| 客户端参数 | 浏览器/系统代理配置 |
| --- | --- |
| `-recv http`（默认） | HTTP 和 HTTPS 代理主机 `127.0.0.1`、端口 `8888`；HTTPS 通过 HTTP CONNECT |
| `-recv socks5` | SOCKS 主机 `127.0.0.1`、端口 `8888`、版本 SOCKS5；需要远端 DNS 时打开相应选项 |

不要在 `-recv http` 入口发送 SOCKS 协议，或直接把浏览器指向混淆服务端端口。浏览器可能默认绕过 localhost，测试本地目标时需调整其绕过列表。浏览器代理插件、系统代理和应用独立配置可能互相覆盖。

## 跨机器运行

服务端将 `-local` 设为可访问的接口地址（例如 `:18888`）；客户端把 `-server` 设为该机器的地址。两端 `-passwd` 与 `-type` 一致。客户端本地监听默认保持回环地址。使用主机/云防火墙限定来源和出口，[混淆密码不提供可靠认证](security.md)。

## 资源和生命周期

两端均支持 `-max-connections 256 -dial-timeout 10s -handshake-timeout 10s -idle-timeout 5m`。握手计时从进程接收连接开始，并包含上游/目标连接时间；`-dial-timeout` 也约束 DNS 查询。零值恢复默认，负数报错。两端独立计时，连接最终受较短预算约束。

正常 TCP EOF 使用半关闭，让另一方向排空响应。错误、取消或双向均无流量超过空闲超时会关闭连接。长时间静默的隧道或应用连接需要根据需求调大 `-idle-timeout`。并发上限前的排队由系统监听 backlog 管理，满载时应用可能等待或连接超时。

HTTP 请求头上限为 32 KiB；请求体流式转发。普通 HTTP 每个本地连接处理一个请求，向目标发送 `Connection: close` 并转发响应到 EOF，客户端后续请求需新建连接。CONNECT 建立后双向转发，保留解析器预读的数据。不提供连接池、HTTP/2 明文代理或普通 HTTP Upgrade 支持。

`Ctrl+C`/SIGTERM 关闭监听、取消拨号、释放活动 socket 并等待处理线程退出。嵌入 Go 应用可以使用 `ClientContext` / `ServerContext` 与 `ProxyOptions`；原有 `Client` / `Server` 继续可用，使用默认资源参数。参数仅影响 proxy 模式，不改变 tunnel 模式的心跳和会话限制。

`too many open files`、HTTP 400/431/502 和 TLS/DNS 问题见[排障文档](troubleshooting.md)。
