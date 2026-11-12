# 社区 PAC、AI 登录与 GitHub 域名

`examples/community-pac/domains.json` 是可维护的明确域名清单，`community-rules.pac` 是固定 GFWList 提交的完整生成快照，`proxy.pac` 是可直接使用的合并产物。

## 分流顺序

1. 局域网、回环和豆包/字节/飞书/火山后缀直连。
2. ChatGPT/Codex、Claude、GitHub 及清单内支持域名走代理。
3. 其余按完整社区清单选择；未命中直连。

服务后缀覆盖根域与点边界子域，不按 URL 文本匹配。共享 WorkOS、验证码、Stripe、Sentry 等依赖按精确主机匹配，不接管整个共享厂商域名。`localhost:1455` 等 Codex OAuth 回调继续直连。豆包保护是域名例外，不是按进程完全排除。

ChatGPT/Codex 规则包含 `openai.com`（含 `auth.openai.com`、`auth0.openai.com`、`api.openai.com`）、`chatgpt.com`（含 `ws.chatgpt.com`）、`oaistatic.com`、`oaiusercontent.com`、`oaistatsig.com`、`openaimerge.com` 及 OpenAI 官方网络说明列出的支持域名。

GitHub 规则包含 `github.com`、`githubusercontent.com`、`githubassets.com`、`github.io`、`githubapp.com`、`github.dev`、`githubcopilot.com`、`ghcr.io`、`githubstatus.com`，以及精确主机 `github-cloud.s3.amazonaws.com`。HTTPS clone、API、raw、release、LFS 与包资源覆盖在这些域名内；SSH Git 和不读取系统代理的工具不由 PAC 自动接管。

## 生成、校验、提供

从仓库根目录运行：

```bash
python3 scripts/build-community-pac.py
node scripts/test-community-pac.js
python3 scripts/serve-community-pac.py
```

默认回环 `http://127.0.0.1:8090/proxy.pac`，只允许读取该 PAC，不暴露目录或密钥。修改 JSON 后重新生成；浏览器需要重新读取 PAC。若 8090 已运行另一个 PAC 服务，不启动第二个服务。

本项目应用代理客户端应使用 `-mode proxy -proxy-scope all -recv http -local 127.0.0.1:8888`，由外部完整 PAC 决定哪些请求进入它。服务端地址与密码由部署者设置，不存入公开清单。此 PAC 不应作为 `-rules-file` 使用：完整社区规则超过项目内部 1024 条规则上限，且包含社区例外语义。

默认示例不修改系统设置、DNS、路由、全局环境变量或 TUN。HTTPS/WebSocket 使用 CONNECT 字节转发，保持系统证书验证；账户权限、验证码、服务端限制或应用是否读取 PAC，不能仅凭域名规则得到解决。命中代理没有附加 `DIRECT` 备用。

## 固定来源与许可证

- GFWList 固定提交：`6de6262bd1bdb6c272b29e44bdbe2ef657c80b14`。
- 来源：<https://raw.githubusercontent.com/gfwlist/gfwlist/6de6262bd1bdb6c272b29e44bdbe2ef657c80b14/gfwlist.txt>。
- 生成器：genpac 3.0.1，<https://github.com/JinnLynn/genpac>；仅改变入口名并跳过生成器较宽松的自定义组，由严格 host 包装处理。
- 社区组保留 33 条直连正则、4398 条代理正则、2 条代理通配，不截断；固定快照不等于实时封禁检测。
- GFWList 许可证见 `GFWLIST-LICENSE.txt`。快照保留源程序及生成信息，不更改原社区含义。
- OpenAI 网络依赖：<https://help.openai.com/en/articles/9247338-network-recommendations-for-chatgpt-errors-on-web-and-apps>。
- Codex 登录及本地回调：<https://developers.openai.com/codex/auth>。
- Claude 网络依赖：<https://code.claude.com/docs/en/network-config?nl=1>。
- GitHub 下载/Packages/LFS 等：<https://docs.github.com/en/actions/reference/runners/github-hosted-runners>。不同业务仍可能使用不在本清单中的第三方域名。
