# Release

发布物现在通过 GitHub Releases 提供，不再依赖外部网盘链接。

## 发布方式

1. 推送形如 `v1.2.3` 的 Git tag。
2. GitHub Actions `Release` workflow 会自动构建发布物并创建/更新对应 Release。
3. Release 页面会附带以下产物：
   - `socks5proxy_client_linux_amd64`
   - `socks5proxy_server_linux_amd64`
   - `socks5proxy_client_windows_amd64.exe`
   - `socks5proxy_server_windows_amd64.exe`
   - `SHA256SUMS`
   - `SHA256SUMS.sig`（仅在仓库配置了 cosign 密钥时生成）

## 校验方式

下载产物后，可使用 `SHA256SUMS` 验证完整性：

```bash
sha256sum -c SHA256SUMS
```

如果仓库配置了 cosign 签名材料，还会额外上传 `SHA256SUMS.sig` 作为可选签名校验文件。
