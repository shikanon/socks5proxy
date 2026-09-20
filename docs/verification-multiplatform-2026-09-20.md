# 多平台客户端验证（2026-09-20）

## 范围

桌面 Linux/Windows/macOS 增加 amd64/arm64 发布矩阵；Android 新增 VpnService 应用；iOS 新增 SwiftUI 应用与 Packet Tunnel 扩展。两端复用 Go 认证、传输、混淆、包过滤及重连核心。

## 已执行

| 检查 | 结果 |
| --- | --- |
| `go test -race -timeout 90s -json ./...`，macOS arm64 / Go 1.26.0 | 192 个测试/子测试通过，无失败；1 个 Linux 专用测试在 macOS 跳过 |
| 移动核心新增用例 | 9 个顶层测试、40 个测试/子测试通过，race 通过 |
| `go vet ./...` | 通过 |
| staticcheck 2026.1 (`v0.7.0`) | 通过；调整两条已有 Linux DNS 错误消息以满足 ST1005 |
| `bash scripts/build-desktop.sh` | 6 个客户端目标及 4 个服务端目标全部构建成功 |
| Windows 包装 | 官方 Wintun 0.14.1 SHA256 验证通过；amd64/arm64 ZIP 均带匹配 DLL 和许可证 |
| Android AAR | arm64-v8a、armeabi-v7a、x86_64 构建成功 |
| Android Gradle | debug APK、未签名 release APK 构建成功；完整 lint 无错误，6 条非阻塞警告（备份声明、图标、文案国际化） |
| Android APK | debug APK v2 签名校验和 16KB ZIP 对齐检查通过 |
| iOS XCFramework | arm64 设备、arm64/x86_64 模拟器构建成功 |
| iOS Xcode 27 / iOS SDK 27 | 模拟器 Debug、设备 Release 应用及扩展均未签名构建通过，最低部署版本 iOS 15 |
| Linux 隔离网络集成 | QUIC/random 和 TCP TLS/random 均通过真实 TUN 转发、重连与恢复测试 |
| Linux 网络单测 | `go test -race ./internal/tunnel/network` 通过，含 macOS 上跳过的 Linux DNS 生命周期测试 |

Android 工具链：JDK 17、Gradle 8.11.1、AGP 8.9.1、API/build-tools 35、NDK 27.2.12479018。gomobile/gobind 固定 `v0.0.0-20260908204917-8b95e45f8d3e`。iOS 项目由 XcodeGen 2.44.1 生成。

本地交付目录 `dist/` 提供桌面各架构二进制、Windows ZIP、`socks5proxy_android_debug.apk`、`socks5proxy_android_release_unsigned.apk`、`tunnelcore-android.aar` 和 `TunnelCore.xcframework`。生成物不纳入 Git；重新生成方法见移动及发布文档。

Linux 集成测试使用独立网络命名空间，覆盖 HTTP 文件哈希、ICMP MTU、UDP/TCP DNS、1/512/1122/4096 字节 UDP 回显、服务端停止后的阻断、重启重连及退出后的路由/防火墙恢复；未修改运行中的公网隧道服务。

## 缺陷分析及用例

测试生成前未发现需要保留的已证实核心缺陷。新增用例覆盖配置默认值与错误输入、私有 CA/TLS 配置、协商参数校验、socket protection 失败、3×3 传输/混淆组合、源/目的地址过滤、队列上限和复制语义、取消认证/阻塞读取、重复生命周期调用、租约不变重连及参数变化终止。

第一轮移动核心 `go test -race -count=1 ./mobile` 全部通过，完成通过用例断言复核；后续全仓回归再次通过。没有通过删除用例或放宽断言消除失败。未要求覆盖率门槛，按测试技能跳过覆盖率统计，完成本地 `utree flush`。

构建过程修正了 Android gomobile 临时模块与 `GOFLAGS=-modfile` 冲突、Swift 对 gomobile 非空字符串返回值的错误导入假设、iOS 15 不可调用的 16+ API，以及扩展版本号不一致。最终脚本在临时源码副本中添加绑定依赖，生产 `go.mod` 不受构建影响。

## 未验证的范围

- Android/iOS 真机联网、蜂窝与 Wi-Fi 切换、锁屏恢复、系统回收及功耗/吞吐尚未测试。
- 未使用 Apple 开发者团队或 provisioning profile 签名，也未生成可真机分发的 IPA；设备 Release 构建成功不代表可直接安装。
- Android release APK 未配置正式签名；debug APK 仅供测试安装。
- Windows/macOS 系统路由的实际安装运行本轮未测试；桌面目标通过交叉编译。Linux 使用真实 TUN 完成集成验证。
- 新 GitHub Actions workflow 尚未在远端运行；本地执行了其中主要构建与验证命令。

运行和构建方法见 [移动客户端文档](mobile-clients.md)。
