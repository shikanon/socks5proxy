# Android / iOS 客户端

移动端连接本项目的 `-mode tunnel` 服务端，与桌面使用相同的认证、IPv4 包格式及 QUIC/TCP 后端。每台设备使用独立的 `client_id` 和服务端登记的 token；`proxy` 模式的密码不能直接替代隧道 token。

## 功能和边界

| 项目 | Android | iOS / iPadOS |
| --- | --- | --- |
| 最低系统 | 8.0 / API 26 | 15.0 |
| 原生网络接口 | VpnService + TUN fd | NEPacketTunnelProvider + packetFlow |
| 架构 | arm64-v8a、armeabi-v7a、x86_64 | arm64 设备；arm64/x86_64 模拟器 |
| 传输 | QUIC、TCP TLS 1.3、TCP 明文 | 相同 |
| 混淆 | none、simple、random | 相同 |
| DNS | 使用服务端下发 DNS | 使用服务端下发 DNS |
| 断线 | 保留 VPN，退避重连 | 保留 VPN，显示 reasserting，退避重连 |
| IPv6 | 不允许 IPv6 family，系统阻断 | 捕获 IPv6 默认路由后丢弃 |
| 密钥保存 | token/CA 仅在进程内；偏好不保存 token | 配置存于共享 Keychain，本机解锁后可用 |

当前隧道协议只支持 IPv4，服务器端点也必须解析到 IPv4。首次连接先解析端点并完成认证，再安装系统 VPN 设置；重连复用该 IPv4 地址，避免 DNS 请求再次进入尚未恢复的 VPN。端点 DNS 变化需要重新连接。

初次认证失败不会安装 VPN。暂时断线时保持 VPN 路由，队列有界，拥塞时丢包。服务器改变客户端 IP、DNS 或 MTU 时，核心终止，应用撤销 VPN，用户需重新连接。手动断开、权限撤销、应用/系统终止也会撤销 VPN；这不等于系统级“始终开启 VPN / 阻止无 VPN 连接”保障。本版本不自动启用 Always-on 或按需连接。

## Android 构建

需要 Go（版本由 `go.mod` 指定）、JDK 17、Gradle 8.11.1、Android command-line tools，以及：

```bash
export ANDROID_HOME="$HOME/Library/Android/sdk"
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/27.2.12479018"
sdkmanager "platforms;android-35" "build-tools;35.0.0" "ndk;27.2.12479018"
bash scripts/build-mobile.sh android
gradle -p apps/android --no-daemon assembleDebug
```

Linux 构建机将 `ANDROID_HOME` 换为实际 SDK 路径。脚本固定 gomobile/gobind 版本，安装在 `.mobile-tools/`，在临时源码副本里添加绑定依赖，不改生产 `go.mod`。AAR 位于 `apps/android/app/libs/tunnelcore.aar` 和 `dist/tunnelcore-android.aar`。

测试安装：

```bash
adb install -r apps/android/app/build/outputs/apk/debug/app-debug.apk
```

在应用里填写服务器 `host:port`、客户端 ID、token，选择与服务端一致的 transport/obfs。私有 CA 需要粘贴 PEM；证书名称与端点不同时填写 TLS 服务器名称。点“连接 VPN”，同意系统授权。通知栏会显示流量和重连状态，可从通知或应用断开。

所有外层 TCP/UDP 套接字都会先调用 `VpnService.protect`，失败则停止连接，重连也执行保护。Go 复制 VPN fd 后持有副本，服务保留原始 `ParcelFileDescriptor`；停止时两者均关闭。单个包不经过 Java/Go JNI，Go 直接读写 fd。

`gradle -p apps/android assembleRelease` 生成未签名 APK。正式分发请配置自己的签名；仓库不附带私钥。

## iOS 构建

需要 macOS、Xcode（含 iOS 与模拟器 SDK）、Go、XcodeGen：

```bash
brew install xcodegen
bash scripts/build-mobile.sh ios
xcodegen generate --spec apps/ios/project.yml
xcodebuild \
  -project apps/ios/Socks5Proxy.xcodeproj -scheme Socks5Proxy \
  -configuration Debug -sdk iphonesimulator \
  -destination 'generic/platform=iOS Simulator' \
  -derivedDataPath dist/ios-build CODE_SIGNING_ALLOWED=NO build
```

`dist/TunnelCore.xcframework` 同时包含设备和模拟器静态库。XcodeGen 生成的项目和 Info.plist 不纳入版本控制。原生应用通过 `NETunnelProviderManager` 配置系统 VPN；扩展读取 Keychain 中的配置并启动 Go 核心。Go 不创建 utun、不调用 shell、不更改系统路由；网络设置由 NetworkExtension 管理。

真机安装：

1. 打开 `apps/ios/Socks5Proxy.xcodeproj`。
2. 为 App 和 PacketTunnel 两个 target 设置相同的 `DEVELOPMENT_TEAM`。
3. 把项目级 `BUNDLE_ID_PREFIX` 改为自己的唯一标识；两个 bundle ID、扩展引用及 Keychain group 从它派生。
4. 确认两个 App ID 的 Network Extensions / Packet Tunnel 权限和共享 Keychain entitlement 与签名配置一致。
5. 选择连接的 iPhone/iPad 构建安装，在应用内填写配置，点“连接 VPN”并同意系统授权。

配置通过 Keychain persistent reference 传给扩展，token 不写入 `providerConfiguration` 或 UserDefaults。Keychain 项使用 `AfterFirstUnlockThisDeviceOnly`；设备重启后需要先解锁一次。模拟器编译成功只能证明构建链路，不能替代真实设备上的 VPN、锁屏重连与系统权限测试。

## Go 嵌入接口

输入 JSON：

```json
{
  "server_addr": "vpn.example.com:443",
  "server_name": "vpn.example.com",
  "client_id": "phone-01",
  "token": "replace-with-your-own-token-at-least-32-characters",
  "ca_pem": "",
  "transport": "quic",
  "obfs": "none",
  "mtu": 1150,
  "dns": ""
}
```

这里的 token 是说明字段，必须替换成真实服务端登记值。默认 transport=quic、obfs=none、MTU=1150；`dns` 可覆盖服务端下发的 IPv4 DNS。`ca_pem` 为空使用系统信任，不提供跳过证书验证选项。

调用顺序：

```text
NewClient(JSON, SocketProtector)
  → Connect() 返回网络参数 JSON
  → 原生 VPN 安装 IP / DNS / MTU / 默认路由
  → Android: AttachFD(fd)；iOS: ReadPacket / WritePacket 桥接
  → Start()
  → Status() 查询 connected / reconnecting / error
  → Close()
```

`Connect`、`ReadPacket` 是阻塞接口，须在后台线程使用。`WritePacket` 复制输入，队列满时丢弃；`Close` 可并发调用并取消认证、重连及包读取。实例为一次性，关闭后创建新实例。

## 验证

核心测试：

```bash
go test -race ./mobile ./internal/tunnel/...
go test -race -timeout 90s ./...
go vet ./...
bash scripts/build-desktop.sh
```

`mobile` 的本地协议对端测试覆盖 3 种传输 × 3 种混淆、保护失败、参数校验、源/目的地址过滤、队列上限、取消认证、取消阻塞读取、同租约重连和参数变化终止。桌面原有握手和传输测试继续覆盖提取后的共享认证。

真机联网、蜂窝/Wi-Fi 切换、锁屏、进程回收及签名分发需要对应设备与账号，不属于本地构建通过的证明范围。最新本地编译结果见 `verification-multiplatform-2026-09-20.md`。
