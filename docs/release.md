# Release

发布物现在通过 GitHub Releases 提供，不再依赖外部网盘链接。

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

下载产物后，可使用 `SHA256SUMS` 验证完整性：

```bash
sha256sum -c SHA256SUMS
```

如果仓库配置了 cosign 签名材料，还会额外上传 `SHA256SUMS.sig` 作为可选签名校验文件。
