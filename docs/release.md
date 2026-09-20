# Release

发布物现在通过 GitHub Releases 提供，不再依赖外部网盘链接。

## 下载与选择

打开 [GitHub Releases](https://github.com/shikanon/socks5proxy/releases)，选择明确版本，下载资产及同一版本的 `SHA256SUMS`。当前源码支持的目标可能尚未包含在历史 Release 中；资产列表以所选版本页面为准，不要通过猜测 URL 判断某平台是否已发布。

| 系统 | 常见 CPU | 客户端文件 |
| --- | --- | --- |
| Linux | x86_64 / aarch64 | `socks5proxy_client_linux_amd64` / `socks5proxy_client_linux_arm64` |
| macOS | Intel / Apple Silicon | `socks5proxy_client_darwin_amd64` / `socks5proxy_client_darwin_arm64` |
| Windows | x64 / ARM64 | 对应 `windows_amd64.zip` / `windows_arm64.zip` 客户端包 |

Linux/macOS 可运行 `uname -m` 查看架构；Windows 在“系统 → 关于 → 系统类型”确认。下载后先校验，Linux/macOS 添加执行权限：

```bash
chmod +x socks5proxy_client_linux_amd64
./socks5proxy_client_linux_amd64 -h
```

macOS 替换为相应 darwin 文件名。Windows 解压 ZIP 后运行 EXE；仅使用应用代理不需要管理员权限，TUN 需要管理员/root 权限。[应用代理及同机示例](proxy.md)、[全局隧道](tunnel.md)、[问题排查](troubleshooting.md)分别覆盖不同模式。

所需目标尚未发布时，使用匹配 `go.mod` 的 Go 工具链从源码构建：

```bash
git clone https://github.com/shikanon/socks5proxy.git
cd socks5proxy
go build -o client ./cmd/client
go build -o server ./cmd/server
```

Windows 本地构建时输出名使用 `client.exe` / `server.exe`。全局 Windows 客户端仍需匹配的 Wintun DLL。Android/iOS 使用下述移动构建入口，桌面 CLI 不是 APK/IPA。

## 发布方式

1. 推送形如 `v1.2.3` 的 Git tag。
2. GitHub Actions `Release` workflow 会自动构建发布物并创建/更新对应 Release。
3. Release 页面会附带以下产物：
   - `socks5proxy_client_darwin_amd64`
   - `socks5proxy_client_darwin_arm64`
   - `socks5proxy_client_linux_amd64`
   - `socks5proxy_client_linux_arm64`
   - `socks5proxy_server_linux_amd64`
   - `socks5proxy_server_linux_arm64`
   - `socks5proxy_client_windows_amd64.exe`
   - `socks5proxy_client_windows_amd64.zip`
   - `socks5proxy_client_windows_arm64.exe`
   - `socks5proxy_client_windows_arm64.zip`
   - `socks5proxy_server_windows_amd64.exe`
   - `socks5proxy_server_windows_arm64.exe`
   - `SHA256SUMS`
   - `SHA256SUMS.sig`（仅在仓库配置了 cosign 密钥时生成）

Windows ZIP 包包含：

- `socks5proxy_client_windows_amd64.exe`
- 官方签名的 Wintun 0.14.1 `wintun.dll`
- `WINTUN_LICENSE.txt`

Windows 全局隧道应使用 ZIP 包并保持 DLL 与 EXE 位于同一目录。独立 EXE 仍可用于原有代理模式。
ARM64 ZIP 包使用 ARM64 EXE 和 ARM64 Wintun DLL。不要混用不同架构的 DLL。

本地可运行 `bash scripts/build-desktop.sh` 构建相同的六种客户端目标及 Linux/Windows 服务端；产物位于 `dist/`。Wintun ZIP 的打包和校验在 Release workflow 中执行。

## 移动构建物

`Mobile clients` workflow 在 master 更新、PR、版本 tag 或手动触发时生成 Actions artifacts：

- `android-client`：三种 ABI 的 Go AAR、可测试安装的 debug APK、未签名的 release APK。
- `ios-client`：设备/模拟器 XCFramework，以及未签名的模拟器应用和扩展。

这些构建物保存在对应 GitHub Actions 运行的 artifacts 中，不自动上传应用商店或附加到 GitHub Release。Debug APK 使用该次构建环境的调试密钥，不保证跨运行覆盖安装。正式 Android 分发需要稳定签名密钥；iOS 真机分发需要 Apple 团队、Network Extension entitlement 和 provisioning profile。构建命令见[移动客户端](mobile-clients.md)。

## 校验方式

在仅下载一个产物时，提取它在同版本 `SHA256SUMS` 中的行进行校验，避免其他未下载文件导致误报。例如 Linux：

```bash
awk '$2 == "socks5proxy_client_linux_amd64" { print }' SHA256SUMS > selected.sha256
test -s selected.sha256 && sha256sum -c selected.sha256
```

macOS：

```bash
awk '$2 == "socks5proxy_client_darwin_arm64" { print }' SHA256SUMS > selected.sha256
test -s selected.sha256 && shasum -a 256 -c selected.sha256
```

Windows PowerShell（在解压之前校验 ZIP）：

```powershell
$asset = "socks5proxy_client_windows_amd64.zip"
$line = Get-Content .\SHA256SUMS | Where-Object { ($_ -split '\s+')[1] -eq $asset }
if (@($line).Count -ne 1) { throw "校验清单中未找到唯一的目标文件" }
$expected = ($line -split '\s+')[0]
if ((Get-FileHash $asset -Algorithm SHA256).Hash -ne $expected) { throw "SHA256 校验失败" }
"SHA256 校验通过"
```

下载全部资产时可以直接运行 `sha256sum -c SHA256SUMS`。checksum 检查下载完整性，不能在校验清单本身不可信时证明发布者身份；应从可信的仓库 Release 获取清单。如果仓库配置了 cosign 签名材料，还会上传 `SHA256SUMS.sig`，可结合独立可信的签名公钥进一步验证。
