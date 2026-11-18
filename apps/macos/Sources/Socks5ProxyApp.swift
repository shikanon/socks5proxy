import SwiftUI
import AppKit

@main
struct Socks5ProxyApp: App {
    @NSApplicationDelegateAdaptor(ClientAppDelegate.self) private var appDelegate
    @StateObject private var store: ProxyStore
    init() {
        SingleInstance.bootstrap()
        _store = StateObject(wrappedValue: ProxyStore())
    }
    var body: some Scene {
        Window("Socks5Proxy", id: "main") {
            ClientView().environmentObject(store)
                .background(MainWindowCapture())
                .onReceive(NotificationCenter.default.publisher(for: SingleInstance.localWake)) { _ in MainWindowRegistry.shared.show() }
        }
        .defaultSize(width: 860, height: 680)
        .windowResizability(.contentMinSize)
        .windowStyle(.hiddenTitleBar)
        .commands {
            CommandGroup(after: .appInfo) {
                Button("刷新代理状态") { Task { await store.refresh() } }.keyboardShortcut("r")
            }
        }
        MenuBarExtra("Socks5Proxy", systemImage: store.snapshot?.ready == true ? "network.badge.shield.half.filled" : "network") {
            Text(store.snapshot?.title ?? "状态待更新")
            Divider()
            Button("打开客户端") { MainWindowRegistry.shared.show() }
            Button("刷新状态") { Task { await store.refresh() } }
            Divider()
            Text("退出界面不停止后台代理")
            Button("退出客户端") { NSApp.terminate(nil) }.keyboardShortcut("q")
        }
    }
}

enum Page: String, CaseIterable, Identifiable {
    case connection = "连接", domains = "域名查询", settings = "设置"
    var id: String { rawValue }
    var symbol: String {
        switch self {
        case .connection: "network"
        case .domains: "magnifyingglass"
        case .settings: "gearshape"
        }
    }
}

struct ClientView: View {
    @EnvironmentObject var store: ProxyStore
    @State private var page: Page = .connection
    @State private var confirmStop = false
    @State private var host = ""
    var body: some View {
        NavigationSplitView {
            VStack(alignment: .leading, spacing: 20) {
                HStack(spacing: 10) {
                    Image(systemName: "network").font(.title2).foregroundStyle(.blue)
                    Text("Socks5Proxy").font(.headline)
                }.padding(.top, 22).padding(.horizontal, 14)
                List(Page.allCases, selection: $page) { item in
                    Label(item.rawValue, systemImage: item.symbol).tag(item).padding(.vertical, 5)
                }.listStyle(.sidebar)
                VStack(alignment: .leading, spacing: 5) {
                    Label(store.snapshot?.title ?? "尚未连接配置", systemImage: "circle.fill")
                        .font(.caption).foregroundStyle(statusColor)
                    Text("本机应用代理 · TCP").font(.caption2).foregroundStyle(.secondary)
                }.padding(16)
            }.navigationSplitViewColumnWidth(190)
        } detail: {
            ScrollView {
                VStack(alignment: .leading, spacing: 22) {
                    HStack {
                        VStack(alignment: .leading, spacing: 5) {
                            Text(page.rawValue).font(.system(size: 28, weight: .bold))
                            Text(subtitle).font(.subheadline).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button { Task { await store.refresh() } } label: { Image(systemName: "arrow.clockwise") }
                            .buttonStyle(.borderless).help("刷新状态").disabled(store.refreshing)
                    }
                    if store.demo {
                        banner("界面演示 · 所有代理操作均被禁用", icon: "eye", color: .blue)
                    }
                    if let error = store.operationError ?? store.error { banner(error, icon: "exclamationmark.triangle", color: .orange) }
                    if let notice = store.notice { banner(notice, icon: "info.circle", color: .blue) }
                    switch page {
                    case .connection: connection
                    case .domains: domains
                    case .settings: settings
                    }
                }.padding(30).frame(maxWidth: 760, alignment: .leading).frame(maxWidth: .infinity)
            }.background(Color(nsColor: .windowBackgroundColor))
        }
        .frame(minWidth: 780, minHeight: 620)
        .alert("停止代理？", isPresented: $confirmStop) {
            Button("取消", role: .cancel) { }
            Button("停止代理", role: .destructive) { Task { await store.perform("stop") } }
        } message: {
            Text("将断开现有代理连接，并恢复本项目保存的网络设置。豆包直连规则不会被改写；重新连接需点击启动。")
        }
    }
    var statusColor: Color { store.snapshot?.partial == true ? .orange : store.snapshot?.ready == true ? .green : store.snapshot?.running == true ? .orange : .secondary }
    var subtitle: String {
        switch page {
        case .connection: "状态清晰，按域名选择节点"
        case .domains: "只查询当前 PAC，不发出目标网站请求"
        case .settings: "管理现有运行环境，不接管全局隧道"
        }
    }
    @ViewBuilder var connection: some View {
        if let state = store.snapshot {
            card {
                HStack(spacing: 18) {
                    Image(systemName: state.ready ? "checkmark.shield.fill" : "network")
                        .font(.system(size: 38, weight: .light)).foregroundStyle(statusColor)
                    VStack(alignment: .leading, spacing: 6) {
                        Text(state.title).font(.title2.weight(.semibold))
                        Text(state.ready ? "HTTP / CONNECT · 127.0.0.1:8888" : state.running ? "管理器运行中，等待可用通道与 PAC" : "启动后由现有管理器验证通道")
                            .font(.callout).foregroundStyle(.secondary)
                    }
                    Spacer()
                    if store.busy { ProgressView().controlSize(.small) }
                    Button(state.running && !state.paused ? "停止" : "启动") {
                        if state.running && !state.paused { confirmStop = true }
                        else { Task { await store.perform("start") } }
                    }.buttonStyle(.borderedProminent).disabled(store.busy || store.demo)
                }
                Divider().padding(.vertical, 10)
                HStack(spacing: 18) {
                    indicator("后台服务", on: state.running)
                    indicator("PAC 服务", on: state.pacListening && state.pacEnabled)
                    indicator("豆包直连", on: state.doubaoDirect)
                }
                if !state.doubaoDirect {
                    Text("当前 PAC 尚未验证；不将离线规则显示为已生效保护。")
                        .font(.caption).foregroundStyle(.secondary).padding(.top, 5)
                }
            }
            HStack {
                Text("域名分流").font(.headline)
                Spacer()
                Text("每 \(state.intervalSeconds / 60) 分钟独立探测").font(.caption).foregroundStyle(.secondary)
            }
            VStack(spacing: 12) {
                ForEach(state.groups) { group in
                    card {
                        HStack(alignment: .top) {
                            Label(group.title, systemImage: group.icon).font(.headline)
                            Spacer()
                            Menu {
                                Button("自动 · 默认优先") { Task { await store.perform("route-auto", group: group.id) } }
                                Divider()
                                ForEach(state.nodes.filter { group.allowedServers.contains($0.id) }) { node in
                                    Button("\(node.title) · \(node.endpoint)") { Task { await store.perform("route", group: group.id, server: node.id) } }
                                        .disabled(group.egressRequired == true && !(group.eligibleServers ?? []).contains(node.id))
                                }
                            } label: {
                                Text(group.manual == nil ? "自动" : store.nodeTitle(group.manual))
                            }.menuStyle(.borderlessButton).fixedSize().disabled(store.busy || store.demo)
                        }
                        HStack(alignment: .firstTextBaseline) {
                            Text(store.nodeTitle(group.selectedServer)).font(.callout.weight(.medium))
                            Text(group.selectedEndpoint.isEmpty ? "等待可用节点" : group.selectedEndpoint)
                                .font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary)
                            Spacer()
                            Button(group.probing ? "探测中" : "探测") { Task { await store.perform("probe", group: group.id) } }
                                .buttonStyle(.borderless).font(.caption).disabled(store.busy || group.probing || store.demo)
                        }.padding(.top, 5)
                        HStack(spacing: 14) {
                            ForEach(group.nodes) { node in
                                HStack(spacing: 4) {
                                    Circle().fill(node.state == "reachable" ? Color.green : node.state == "unreachable" || node.state == "policy_denied" ? Color.orange : Color.gray).frame(width: 5, height: 5)
                                    Text("\(store.nodeTitle(node.id)) \(group.egressRequired == true && node.eligible != true ? (node.egressState == "denied" ? "地区排除" : "地区待确认") : node.label)")
                                    if let country = node.country, group.egressRequired == true { Text(country) }
                                    if let ms = node.responseMs { Text("\(Int(ms)) ms").monospacedDigit() }
                                }.font(.caption2).foregroundStyle(.secondary)
                            }
                        }.padding(.top, 7)
                        Text("默认 \(store.nodeTitle(group.defaultServer)) · 仅新连接按偏好与故障回退选择")
                            .font(.caption2).foregroundStyle(.tertiary).padding(.top, 4)
                        if group.egressRequired == true {
                            Text("OpenAI / Codex · Claude，共用节点；排除 HK / MO，地区未知不可选")
                                .font(.caption2).foregroundStyle(.secondary).padding(.top, 5)
                        }
                    }
                }
            }
            Text("端点可达不等于登录或模型生成成功。退出此界面不会停止后台代理。")
                .font(.caption).foregroundStyle(.secondary)
        } else {
            card {
                Label("选择已部署的项目目录", systemImage: "folder").font(.headline)
                Text("本版连接已有 socks5proxy 运行环境，不包含生产密钥或独立安装的代理核心。")
                    .font(.callout).foregroundStyle(.secondary).padding(.top, 6)
                Button("选择项目目录…", action: chooseProject).padding(.top, 12)
            }
        }
    }
    var domains: some View {
        VStack(alignment: .leading, spacing: 18) {
            card {
                HStack {
                    TextField("例如 github.com", text: $host).textFieldStyle(.roundedBorder)
                        .onSubmit { Task { await store.query(host) } }.accessibilityLabel("查询域名")
                    Button("查询") { Task { await store.query(host) } }
                        .buttonStyle(.borderedProminent).disabled(host.isEmpty || store.busy || store.demo)
                }
                Text("仅接收域名，不接收带 code / state 的授权链接。")
                    .font(.caption).foregroundStyle(.secondary).padding(.top, 8)
            }
            if let result = store.queryResult {
                card {
                    Label(result.route == "DIRECT" ? "直连" : "走代理", systemImage: result.route == "DIRECT" ? "arrow.up.right" : "network")
                        .font(.title2.weight(.semibold)).foregroundStyle(.blue)
                    Text(result.host ?? "").font(.system(.body, design: .monospaced)).padding(.top, 8)
                    Text([result.reason, result.match].compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: " · "))
                        .font(.callout).foregroundStyle(.secondary).padding(.top, 4)
                }
            }
            Text("结果来自当前回环 PAC，只代表规则选择，不是访问历史或转发成功证明。PAC 不可用时不会自动换成旧文件。")
                .font(.callout).foregroundStyle(.secondary)
        }
    }
    var settings: some View {
        VStack(alignment: .leading, spacing: 18) {
            card {
                HStack {
                    VStack(alignment: .leading, spacing: 5) {
                        Text("登录后自动启动").font(.headline)
                        Text("控制代理后台服务，不是登录前系统 VPN").font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Toggle("登录后自动启动", isOn: Binding(get: { store.snapshot?.autostart ?? false }, set: { value in Task { await store.perform(value ? "autostart-on" : "autostart-off") } }))
                        .toggleStyle(.switch).labelsHidden().disabled(store.busy || store.snapshot?.installed != true || store.snapshot?.autostartVerified == false || store.demo)
                    if store.snapshot?.autostartVerified == false { Text("状态待确认").font(.caption).foregroundStyle(.secondary) }
                }
                Text("关闭自启动不会结束当前代理；主动停止会保留暂停状态，直到再次启动。")
                    .font(.caption).foregroundStyle(.secondary).padding(.top, 12)
            }
            card {
                Text("运行环境").font(.headline)
                Text(store.projectPath).font(.system(.caption, design: .monospaced)).textSelection(.enabled).lineLimit(3).padding(.top, 8)
                Button("更换项目目录…", action: chooseProject).padding(.top, 12).disabled(store.busy)
                Text("仅选择自己的可信项目；适配层会运行其中的管理脚本。")
                    .font(.caption).foregroundStyle(.secondary).padding(.top, 6)
            }
            card {
                Text("连接边界").font(.headline)
                VStack(alignment: .leading, spacing: 8) {
                    Label("保留豆包域名直连，不做全局 TUN", systemImage: "shield")
                    Label("不解密 HTTPS，保持目标 TLS 验证", systemImage: "lock")
                    Label("界面不读取密码、私钥或授权票据", systemImage: "key.slash")
                    Label("后台服务独立于界面运行", systemImage: "square.stack.3d.up")
                }.font(.callout).foregroundStyle(.secondary).padding(.top, 12)
            }
        }
    }
    func chooseProject() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = false; panel.canChooseDirectories = true; panel.allowsMultipleSelection = false
        panel.message = "选择自己可信的 socks5proxy 项目目录。不会导入或覆盖密钥。"
        if panel.runModal() == .OK, let url = panel.url { store.setProject(url) }
    }
    func indicator(_ title: String, on: Bool) -> some View {
        Label(title, systemImage: on ? "checkmark.circle.fill" : "circle.dashed").font(.caption).foregroundStyle(on ? Color.green : Color.secondary)
    }
    func banner(_ text: String, icon: String, color: Color) -> some View {
        Label(text, systemImage: icon).font(.callout).foregroundStyle(color).padding(12)
            .frame(maxWidth: .infinity, alignment: .leading).background(color.opacity(0.07), in: RoundedRectangle(cornerRadius: 10))
    }
    func card<Content: View>(@ViewBuilder _ content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 0, content: content).padding(18).frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 14))
            .overlay(RoundedRectangle(cornerRadius: 14).strokeBorder(Color.primary.opacity(0.06)))
    }
}
