# Multi-platform Clients Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Provide Linux, Windows, macOS CLI builds and native Android/iOS global IPv4 VPN clients using the same authenticated QUIC/TCP tunnel protocol.

**Architecture:** Extract authentication into a platform-independent session package. A gomobile package owns transport, packet validation, bounded queues, cancellation and reconnect; Android supplies protected sockets and a VPN file descriptor, while iOS exchanges packets through NEPacketTunnelFlow. Native operating systems own routing, DNS and VPN consent.

**Tech Stack:** Go 1.26, quic-go, gomobile, Java/Android VpnService, SwiftUI/NetworkExtension, Xcode, Gradle, GitHub Actions.

The referenced superpowers execution skills are unavailable in this installation. Execute directly in the isolated `feat/multiplatform-clients` worktree under the existing implementation authorization.

**Execution result:** All five work packages below are implemented. Desktop builds, Android AAR/APKs/lint, iOS unsigned simulator/device builds, Go race/vet/staticcheck and Linux QUIC/TCP TUN integration passed. See `docs/verification-multiplatform-2026-09-20.md`; physical mobile devices and signing remain explicitly outside the completed validation.

---

## 1. Portable transport and authentication

Files: `internal/tunnel/session/auth.go`, `internal/tunnel/client/client.go`, `internal/tunnel/transport/{connection,tcp,quic}.go`.

- [x] Move the existing challenge/proof and QUIC authentication body into `session.Connect`, preserving protocol semantics. Keep the desktop `connect` wrapper so existing tests continue exercising the same implementation.
- [x] Add the socket-control type and optional dial entry point:

```go
type SocketControl func(network, address string, socket syscall.RawConn) error
func DialTunnelWithControl(ctx context.Context, addr string, cfg *tls.Config, kind string, control SocketControl) (Conn, error)
```

- [x] TCP uses `net.Dialer.Control`; QUIC uses `net.ListenConfig.Control` and owns/closes its UDP socket. A protection error must abort before sending.
- [x] Run `go test ./internal/tunnel/client ./internal/tunnel/transport` and preserve all previous authentication/cancellation behavior.

## 2. Embeddable mobile API

Files: `mobile/{client,config,fd_android,fd_other}.go`, `mobile/*_test.go`.

- [x] Implement this gomobile-safe public boundary:

```go
type SocketProtector interface { ProtectSocket(fd int) bool }
func NewClient(configJSON string, protector SocketProtector) (*Client, error)
func (c *Client) Connect() (string, error)
func (c *Client) Start() error
func (c *Client) AttachFD(fd int) error
func (c *Client) WritePacket(packet []byte) error
func (c *Client) ReadPacket() ([]byte, error)
func (c *Client) Status() string
func (c *Client) Close() error
```

- [x] JSON input keys: `server_addr`, `server_name`, `client_id`, `token`, `ca_pem`, `transport`, `obfs`, `mtu`, `dns`. Default QUIC, none, MTU 1150. Reject invalid token, endpoint, MTU and DNS.
- [x] Connect resolves IPv4 before VPN setup, authenticates and returns `client_ipv4`, `server_ipv4`, `dns_ipv4`, `endpoint_ipv4`, `mtu`. Start relays with bounded queues and retries after disconnect, retaining native VPN routes. Changed negotiated parameters terminate the core with an actionable status.
- [x] Close cancels dialing, queue operations and I/O. Android duplicates and takes ownership only of the duplicated descriptor; other platforms use packet queues.
- [x] Follow the seven-step unit-test workflow before writing tests. Verify rejected protection, bad configuration, source/destination filtering, blocked reads canceled by Close, reconnect and changed lease behavior.
- [x] Run `go test -race ./mobile ./internal/tunnel/...`.

## 3. Android application

Files: `apps/android/{settings.gradle,build.gradle,gradle.properties}`, `apps/android/app/{build.gradle,src/main/AndroidManifest.xml,src/main/java/com/shikanon/socks5proxy/*.java}`, `scripts/build-mobile.sh`.

- [x] Add native configuration fields for endpoint, client ID, token, CA PEM, SNI and transport/obfs selectors. Persist only non-secret preferences.
- [x] Obtain VPN consent with `VpnService.prepare`; start a foreground VPN service. Load the Go AAR, connect on a worker, establish IPv4 default route and DNS, attach the descriptor and start the core.
- [x] Route every outer TCP/UDP socket through `VpnService.protect`. Leave IPv6 disallowed so unsupported IPv6 cannot bypass the VPN. Retain the VPN during reconnect. Stop closes the Go client and descriptor.
- [x] Build AAR for arm64, arm, amd64 and APK using documented SDK/NDK/JDK versions. Keep generated binaries outside version control.

## 4. iOS application

Files: `apps/ios/{project.yml,App/*.swift,PacketTunnel/*.swift,App/*.entitlements,PacketTunnel/*.entitlements}`, build script.

- [x] Add SwiftUI configuration/connection UI and Keychain storage for token/CA. Configure a `NETunnelProviderManager` with a Packet Tunnel extension.
- [x] Provider calls Connect before installing network settings, captures the IPv4 default route, configures DNS and an IPv6 sink route, then starts the core and exchanges packets using `NEPacketTunnelFlow`.
- [x] Close stops both directions and completes cancellation. Reconnect preserves settings; terminal errors cancel the tunnel. Check start/stop races and report status in the UI.
- [x] Build an iOS/simulator XCFramework and generate an Xcode project with XcodeGen. Run an unsigned simulator build. Device installation requires the user's Apple team, entitlement and provisioning profile.

## 5. Desktop/release integration

Files: `.github/workflows/{ci,release,mobile}.yml`, `scripts/build-desktop.sh`, `.gitignore`, `README.md`, `docs/{release,mobile-clients}.md`.

- [x] Build Darwin/Linux/Windows amd64 and arm64 clients and Linux/Windows servers. Package the matching Wintun DLL/license for both Windows architectures.
- [x] Add CI builds for Go regression, Android APK/AAR, and unsigned iOS app/XCFramework. Do not automatically create signed mobile store releases.
- [x] Document platform matrix, configuration, build commands, artifacts, IPv4-only behavior and exact validation achieved.
- [x] Run `go test ./...`, `go vet ./...`, desktop cross-builds, Android assemble and unsigned Xcode build where toolchains are available.
- [x] Prepare verified work for commit and fast-forward integration into the original checkout, preserving its existing untracked diagnostics.
