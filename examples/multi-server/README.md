# macOS 用户登录启动与 HTTP 代理主备

本示例把已有 `random` TCP 应用代理、完整社区 PAC 和用户登录任务组合起来。`scripts/multi-server-manager.py` 提供逐连接主备选择，`scripts/multi-autostart-control.py` 管理 LaunchAgent，仓库根目录 `proxy-service` 是统一控制命令。

## 已有部署与新部署的区别

已经配置好的私有运行目录可直接使用：

```bash
./proxy-service status
./proxy-service start
./proxy-service stop
./proxy-service backup
./proxy-service primary
./proxy-service auto
./proxy-route google.com www.doubao.com
```

新 clone **不会自动安装或修改网络**。`dist/` 不进入 Git，因此新 clone 没有生产地址、客户端二进制、代理 secret、PID、macOS 权限或服务器密码。以下源码用于准备一个新私有运行目录，不能把只 clone 成功称为已部署。

## 拓扑和契约

`系统 PAC → 127.0.0.1:8888 HTTP/CONNECT → random TCP 127.0.0.1:18900 → 可用远端`

- 8888 是 HTTP/CONNECT，不是 SOCKS5。
- 配置顺序是优先级，正常主服务器优先；不可用时尝试备用。支持 2–8 个 IPv4 TCP 后端，后端共享 random 配置和 secret。
- 健康检查使用独立 HTTP 客户端访问真实 Google HTTPS，保留 TLS 验证。每次检查结束后等待 10 秒，单次预算 8 秒；连续两次失败下线、连续两次成功恢复。TCP 建立预算 3 秒，实际切换时间不是固定保证。
- 只在向后端发送应用数据前尝试另一个后端；不重放已发送数据。新连接可改选，已有连接不因优先级变化强制迁移。真正故障的后端仍可能中断已有会话。
- 无健康后端时拒绝代理连接，不改为直连；管理器继续探测。固定回环端口、128 条 relay 和 300 秒 socket 超时是当前实现边界。
- `primary`/`backup` 是偏好，不锁死唯一后端；未命名为 primary/backup 的额外后端按配置顺序选。
- PAC 的豆包/字节/飞书/火山域名优先 DIRECT，但不是按进程排除；第三方和新域名仍需补充。完整社区快照和 AI/GitHub/X/Meta 清单来自 `examples/community-pac/`。
- 这是 macOS 用户登录后的 LaunchAgent，不是开机未登录系统 daemon、负载均衡或 TUN。

## 私有运行目录准备

前提：Python 3、curl、对应架构的本项目 client；macOS 的 Wi-Fi 服务对应 en1。本示例的 `proxy-settings.m` 和 community-control 只针对这个明确网络服务，不自动选择或修改其他服务。

从仓库根目录准备新的目录（已有部署不要覆盖）：

```bash
mkdir -p dist/overseas-proxy/community-pac
cp examples/multi-server/direct-client-control.py dist/overseas-proxy/
cp examples/multi-server/community-control.py dist/overseas-proxy/community-pac/
cp examples/multi-server/pac-server.py dist/overseas-proxy/community-pac/
cp examples/multi-server/proxy-settings.m dist/overseas-proxy/community-pac/
cp examples/multi-server/multi-server.example.json dist/overseas-proxy/multi-server.json
# Go 构建产物也可来自经过校验的已有发布版本。
go build -o dist/overseas-proxy/client ./cmd/client
# 编译需要已由使用者完成 Xcode/Command Line Tools 的许可和权限。
xcrun clang -fobjc-arc -framework Foundation -framework SystemConfiguration \
  dist/overseas-proxy/community-pac/proxy-settings.m \
  -o dist/overseas-proxy/community-pac/proxy-settings
python3 scripts/build-community-pac.py \
  --output dist/overseas-proxy/community-pac/combined.pac \
  --wrapper-output dist/overseas-proxy/community-pac/direct-first.js
cp examples/community-pac/community-rules.pac dist/overseas-proxy/community-pac/proxy.pac
```

示例 `192.0.2.10` 和 `198.51.100.20` 是文档专用地址，不是真实服务。部署者把 `multi-server.json` 中 endpoint 改为自己的已部署地址；不会上传到仓库。选择器固定为 `127.0.0.1:18900`。将同两台服务器一致的 secret 保存在 `dist/overseas-proxy/proxy.secret`，权限 0600；不要放到 JSON、启动项、Git 或命令历史。

首次运行还需要可信 `transport.json`，例如保存当前已验证的 `direct` endpoint，以便初次接管失败时恢复原客户端：

```json
{"mode":"direct","server":"192.0.2.10:8080"}
```

若尚无原通道，该字段仍填写真实可用的第一台服务端，不使用文档地址。公开 `direct-client-control.py` 适配器只支持 direct/multi；它不依赖私人部署中的历史 `before-new-server`、SSH 登录或固定公网地址。原私人部署可继续使用已验收的适配器，不必用示例替换它。

## 安装与运行边界

```bash
python3 scripts/multi-autostart-control.py install --runtime dist/overseas-proxy
./proxy-service start
```

`install` 创建当前用户 LaunchAgent 并加载；`start` 等待真实主备通道就绪。重复启动不重启正常组件；`stop` 写暂停标记、卸载任务并恢复本项目 PAC 设置，只有显式 start 才恢复。异常退出由 launchd 重启；健康/client/PAC 由管理器恢复。

启动项使用安装时 Python 的绝对路径，日志写 `~/Library/Logs`。项目磁盘、路径和 Python runtime 必须在登录时可用；项目移动或 runtime 删除后应重新检查启动项。macOS 磁盘访问与网络设置授权须由使用者完成，脚本不绕过权限，不接受许可，不重启机器。

本机 adapter 保存 transport/connection 状态；PAC snapshot 首次创建后不覆盖。公开 PAC 控制器拒绝覆盖另一个启用的 PAC。若原有固定 HTTP/HTTPS 代理，恢复时保留它们的原始启用状态，故此示例适用前应检查自己的网络环境。

服务器必须独立部署可达的应用与来源受限入口，并由服务器管理员配置 systemd 开机启动。仓库脚本**不自动 SSH 登录、部署服务、放宽防火墙或 enable 任意服务**。BBR 的系统支持和入口设置见 `docs/tcp-bbr.md`；本机主备脚本不切换全局拥塞控制。

## 测试与证据范围

```bash
python3 scripts/test-multi-server-manager.py -v
python3 scripts/test-multi-runtime.py
```

前者覆盖主备迟滞、逐连接固定、TCP建立前重试、无后端拒绝、偏好、半关闭上传及僵尸/陌生进程识别。后者在临时目录验证公开适配器、PAC helper 接口、状态保存、HTTP固定路径和正常退出，缺少本机私有 dist 时也能运行。两者不修改系统代理或生产端口。

现有私人 Mac 部署还完成过真实远端入口停止/恢复、Google/出口切换、TLS keep-alive 不随偏好迁移、健康/client/PAC/manager 退出恢复、手动停止及冷启动、原生系统 Google代理/豆包直连等验收。原始证据因包含生产状态保存在私人 dist，不提交到公开仓库；该验收不意味着每个新 clone 或新环境已自动通过。机器重启和退出登录未用于实测；公开新辅助源码也不能冒充原私人辅助脚本的完全同版本验收。

## 安全边界

random 仅是字节混淆，不是安全加密或可靠认证；来源限制不是强认证。HTTPS 保持默认 TLS 校验。客户端 `-passwd` 由既有 CLI 接口传入，运行进程参数可能被同用户/管理员读取，不承诺操作系统级秘密隐藏。

状态命令显示健康、偏好、活动连接和接受计数，不是域名访问历史。`proxy-route` 是 PAC 规则查询，不是实际转发成功证明。配置/辅助脚本仅使用自己可信的本地文件；脚本导入 runtime Python，不提供执行不可信代码的隔离环境。
