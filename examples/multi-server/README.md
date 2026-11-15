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
./proxy-service latency
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
- `primary`/`backup`/`backup2` 是已配置同名后端的偏好，不锁死唯一后端；未配置对应名称时拒绝修改偏好，其他后端按配置顺序选。
- 状态心跳独立于 PAC 联网校验发布，慢速校验不阻塞后台健康状态更新。
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

若尚无原通道，该字段仍填写真实可用的第一台服务端，不使用文档地址。公开 `direct-client-control.py` 适配器支持 direct/multi/domain；它不依赖私人部署中的历史 `before-new-server`、SSH 登录或固定公网地址。原私人部署可继续使用已验收的适配器，不必用示例替换它。

## 安装与运行边界

```bash
python3 scripts/multi-autostart-control.py install --runtime dist/overseas-proxy
./proxy-service start
```

`install` 创建当前用户 LaunchAgent 并加载；`start` 等待真实主备通道就绪。重复启动不重启正常组件；`stop` 写暂停标记、卸载任务并恢复本项目 PAC 设置，只有显式 start 才恢复。异常退出由 launchd 重启；健康/client/PAC 由管理器恢复。

启动项使用安装时 Python 的绝对路径，日志写 `~/Library/Logs`。项目磁盘、路径和 Python runtime 必须在登录时可用；项目移动或 runtime 删除后应重新检查启动项。macOS 磁盘访问与网络设置授权须由使用者完成，脚本不绕过权限，不接受许可，不重启机器。

本机 adapter 保存 transport/connection 状态；PAC snapshot 首次创建后不覆盖。公开 PAC 控制器拒绝覆盖另一个启用的 PAC。若原有固定 HTTP/HTTPS 代理，恢复时保留它们的原始启用状态，故此示例适用前应检查自己的网络环境。

服务器必须独立部署可达的应用与来源受限入口，并由服务器管理员配置 systemd 开机启动。仓库脚本**不自动 SSH 登录、部署服务、放宽防火墙或 enable 任意服务**。BBR 的系统支持和入口设置见 `docs/tcp-bbr.md`；本机主备脚本不切换全局拥塞控制。

## 可选的30分钟HTTPS响应择优

`latency_selection.enabled=true` 启用内置周期，不需要另建cron或重复LaunchAgent。无该配置时保持原固定优先级，示例默认不启用。每轮访问固定 `https://www.google.com/generate_204`，经每个后端独立HTTP客户端采样3次，至少2次HTTP204且TLS校验成功才有效，以 `curl time_starttransfer` 的中位毫秒耗时排序。该耗时包含本机代理、远端TCP/TLS建立和HTTPS首响应，不是ping RTT或下载带宽。

第一次启动在至少一个后端健康后立即测一轮；后续轮次开始相隔1800秒，每轮完成后评估新连接优先级。当前节点有效时，挑战节点须同时快15%和100ms才替换；这些是可配置防抖默认值，不是最优性能收益结论。当前节点无有效样本时可选择其他健康有效节点；全失败时保持近期排序，超过两轮周期失效后回配置顺序。健康检查独立高频执行，不等30分钟才故障回退，拨测结果不能把不健康节点强行设为健康。

`primary`/`backup`/`backup2`手动偏好高于性能排序，`auto`取消手动偏好并恢复性能择优。`./proxy-service latency`只读显示本轮样本、中位响应、所选节点、最后与下一次拨测时间；`status`也带该状态。`latency-state.json`保存最近48轮和与配置绑定的指纹，管理器重载保留下一轮时间，配置/端点变化不复用旧结果。休眠或离线后最多补测一轮，不补跑全部错过的轮次。

性能排序不改变PAC、服务器、BBR或来源策略，也不主动迁移已有连接。该模式证明的是按已确认指标动态选择，不保证全站性能或下载速度更快。

## 可选的域名分组探针与切换

`domain-server.example.json` 是三节点文档地址示例：普通组默认 `backup`，OpenAI和Claude默认 `primary`。文档地址不能实际联网，部署者须替换为自己已验证的端点；配置不含秘密。默认基础示例仍保持域名功能未启用。

启用 `domain_routes.enabled=true` 后，数据路径变为：

`系统PAC → 127.0.0.1:8888 域名HTTP/CONNECT入口 → 对应节点的独立HTTP client → random TCP远端`

- 8888由Python前置入口持有，不再由Go client连至18900统一选择后端。18900旧选择器保留兼容，但不是域名流量的实际路径。
- 普通HTTP按首个绝对URL分组，下游Go client每条普通HTTP连接仅处理一次请求；HTTPS按CONNECT目标host分组，不解密TLS、不读取HTTPS正文。
- 精确主机先匹配，后缀使用点边界和最长匹配；未命中属于 `ordinary`。共享服务只列精确主机，不扩大整个第三方域名。示例将共享的 `challenges.cloudflare.com`归于openai，不代表能按一个共享host区分服务或按进程选组。
- PAC仍决定代理还是直连。完整社区清单与豆包优先DIRECT不拆分；域名组只决定已进入8888的流量使用哪个后端。
- 各组每1800秒启动一轮，3遍候选×探针，只读GET/HEAD、12秒预算、TLS验证与64KiB响应上限；多探针以最差状态合并，至少2个可达样本才标为reachable。完成后保留当前轮原始结果和下一轮时间；没有全局48轮历史的同等承诺。
- 自动模式依次选择手动偏好、组默认、允许候选；响应毫秒用于诊断，不按速度替换可用默认。域名模式会暂停旧全局latency排序，不应同时把两种模式称为已生效。
- `allowed_servers`限制流量候选，必须包含默认且是 `probe_servers`子集。普通组同时参考Google健康；特殊组已探测后使用自己的reachable/unknown状态，不被Google页面单独失败连带下线。unknown不代表应用成功。
- 明确地区拒绝记录为policy_denied，普通403/429记录为unknown；401/405只证明无凭据端点网络响应，不证明地区资格、登录或功能。策略拒绝节点不会用于该组流量；仅在管理员授权的候选中回退，不保证能满足平台地区或账户政策。
- CONNECT在200与应用字节提交前可尝试其他候选，失败有20秒组内连接冷却；提交后不重放。无候选返回503，不偷偷直连。已有连接固定原节点，管理器重载或真实故障仍可能断开连接。
- 前置层128并发，头上限32KiB和5秒总预算；双向流式转发共享300秒空闲时钟、有限缓冲与半关闭保护。
- `domain-state.json`按配置指纹保存组状态、下一轮时间，重载不自动重复已完成轮次；休眠后最多补一轮。手动probe请求有独立记录，完成后不因重载重复。

```bash
./proxy-service routes
./proxy-service routes --group openai
./proxy-service route --group openai --server backup
./proxy-service route-auto --group openai
./proxy-service probe --group claude
```

这些命令分别查询、保存该组偏好、取消偏好或请求一轮探针，不重启管理器。`primary`/`backup`/`backup2`及`auto`在域名模式只修改ordinary组，特殊组不受影响。JSON配置文件本身不热加载；必须受控重载，入口变更会影响已有连接，应保留旧配置和恢复路径。状态是本机可信文件，不是远端应用登录凭证。

`routes`提供有限最近接受记录和探针状态，但不能证明TLS隧道内某个请求返回或登录成功；已有长期连接可能不出现在最新32条记录中。`proxy-route`仍只是PAC选择。

## Codex进程专用代理

`./codex-proxy.command`为桌面应用及内置CLI单独传入代理环境；`--check`核对继承，`--cli -- login status`调用官方状态命令。它不设置launchd全局环境、不改豆包DIRECT，详见 [Codex专用代理](../../docs/codex-proxy.md)。应用可忽略代理变量，GUI/认证/模型生成必须分别验收。

## 测试与证据范围

```bash
python3 scripts/test-multi-server-manager.py -v
python3 scripts/test-multi-runtime.py
python3 scripts/test-latency-selection.py -v
python3 scripts/test-domain-routing.py -v
python3 scripts/test-codex-proxy-launch.py -v
```

前者覆盖主备迟滞、逐连接固定、TCP建立前重试、无后端拒绝、偏好、半关闭上传及僵尸/陌生进程识别。后者在临时目录验证公开适配器、PAC helper 接口、状态保存、HTTP固定路径和正常退出，缺少本机私有 dist 时也能运行。两者不修改系统代理或生产端口。

现有私人 Mac 部署还完成过真实远端入口停止/恢复、Google/出口切换、TLS keep-alive 不随偏好迁移、健康/client/PAC/manager 退出恢复、手动停止及冷启动、原生系统 Google代理/豆包直连等验收。原始证据因包含生产状态保存在私人 dist，不提交到公开仓库；该验收不意味着每个新 clone 或新环境已自动通过。机器重启和退出登录未用于实测；公开新辅助源码也不能冒充原私人辅助脚本的完全同版本验收。

## 安全边界

random 仅是字节混淆，不是安全加密或可靠认证；来源限制不是强认证。HTTPS 保持默认 TLS 校验。客户端 `-passwd` 由既有 CLI 接口传入，运行进程参数可能被同用户/管理员读取，不承诺操作系统级秘密隐藏。

状态命令显示健康、偏好、活动连接和接受计数，不是域名访问历史。`proxy-route` 是 PAC 规则查询，不是实际转发成功证明。配置/辅助脚本仅使用自己可信的本地文件；脚本导入 runtime Python，不提供执行不可信代码的隔离环境。
