# Codex 的进程专用 HTTP 代理

本项目提供 `codex-proxy.command` 和 `scripts/codex-proxy-launch.py`，只为新启动的 Codex 桌面应用及正常继承环境的子进程配置本机代理，不修改系统全局环境、网络服务、DNS、默认路由或其他应用。

## 前提与使用

- macOS、Python 3，以及已安装的 Codex 桌面客户端。
- 默认客户端路径为 `/Applications/ChatGPT.app`，Bundle ID须为 `com.openai.codex`。其他安装路径可用 `--app` 明确指定。
- 本项目 HTTP/CONNECT 代理已经在 `127.0.0.1:8888` 运行。8888不是SOCKS5。
- 正常退出既有Codex实例后，再从仓库根目录运行：

```bash
./codex-proxy.command
./codex-proxy.command --check
```

也可双击 `.command` 文件，但它依赖同目录的 `scripts/`，不能作为独立客户端搬走。桌面启动分支拒绝已有桌面或内置CLI实例，不强杀任务，不清除登录缓存。显式 `--cli` 分支直接执行内置CLI，不受该实例保护限制。

使用应用内置CLI及同一代理环境：

```bash
./codex-proxy.command --cli -- --version
./codex-proxy.command --cli -- login status
./codex-proxy.command --cli -- doctor --network-only --json
```

`doctor` 是否可用取决于所安装客户端版本。它是网络诊断，不是模型生成测试；认证失败、401/405等响应不能直接判为应用可用。

## 实现方式

macOS应用由 `open --env` 启动，逐项传入：

```text
HTTP_PROXY=http://127.0.0.1:8888
HTTPS_PROXY=http://127.0.0.1:8888
ALL_PROXY=http://127.0.0.1:8888
http_proxy=http://127.0.0.1:8888
https_proxy=http://127.0.0.1:8888
all_proxy=http://127.0.0.1:8888
NO_PROXY=localhost,127.0.0.1,::1
no_proxy=localhost,127.0.0.1,::1
NODE_USE_ENV_PROXY=1
```

Chromium界面网络层另使用：

```text
--proxy-server=http://127.0.0.1:8888
--proxy-bypass-list=localhost;127.0.0.1;[::1]
```

`HTTPS_PROXY`仍指向HTTP代理入口，站点HTTPS通过CONNECT隧道保留TLS信任和主机名验证。没有证书校验绕过或TLS解密。

脚本未使用 `launchctl setenv`，也不写 `.zshrc`；这些设置只属于该次应用启动，正常继承的子进程会得到相同环境。`--check`读取当前进程中的代理变量，只报告与配置是否一致，不记录完整环境或凭据。

启动记录在忽略Git的 `dist/overseas-proxy/codex-proxy-launch.json` 中。它包含进程元数据和匹配布尔值，不保存令牌、Cookie或应用日志。

## 边界

- 环境继承不等于操作系统级强制拦截；忽略代理变量、重新构建环境或自行重启的组件仍需单独验证。
- 普通Dock启动或应用升级自行重启，不能假设保留本次代理环境。再次从专用启动器启动会重新设置并核验。
- Codex启动的其他工具也可能继承这些变量。独立运行的豆包工作进程不继承它们；本项目系统PAC的豆包域名直连规则保持不变。
- 对于进入8888的请求，启用域名路由后仍按目标域名选择各组后端。IP地址不能直接当作域名身份。
- 代理路径可达、登录完成、WebSocket握手、主界面加载及模型生成是不同验收层次。不能只靠公开API401、页面302或环境变量存在宣布登录或完整应用成功。
- 回环1455是Codex短时OAuth回调，不是本项目代理端口。会话结束后该端口可能不再监听；不能重放旧callback URL，密码、验证码和授权码应留在客户端自己的认证流程中。
- 更换网络路径不证明满足平台地区、账户或组织资格，不应将策略拒绝误写为普通连通性成功。

## 恢复与测试

正常退出Codex后用原应用入口启动即可不再由本启动器设置环境，不需要撤销全局网络配置，也不需要删除登录缓存。系统PAC继续按原配置运行。

```bash
python3 scripts/test-codex-proxy-launch.py -v
bash -n codex-proxy.command
```

隔离测试覆盖环境复制、大小写代理变量、回环例外、应用身份校验、重复实例保护、LaunchServices参数及仅输出布尔值的环境检查。测试不启动真实应用、不修改系统网络；真实GUI验收依赖使用者的客户端版本和环境。
