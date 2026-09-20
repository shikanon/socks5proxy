import SwiftUI

@main
struct Socks5ProxyApp: App {
    var body: some Scene { WindowGroup { ContentView() } }
}

struct ContentView: View {
    @StateObject private var vpn = VPNModel()
    @AppStorage("server") private var server = ""
    @AppStorage("clientID") private var clientID = ""
    @AppStorage("serverName") private var serverName = ""
    @AppStorage("transport") private var transport = "quic"
    @AppStorage("obfs") private var obfs = "none"
    @State private var token = ""
    @State private var ca = ""

    var body: some View {
        NavigationView {
            Form {
                Section {
                    Label(vpn.status, systemImage: vpn.active ? "lock.shield" : "network")
                        .accessibilityLabel("VPN 状态：\(vpn.status)")
                }
                Section("服务器") {
                    TextField("服务器 host:port", text: $server)
                    TextField("客户端 ID", text: $clientID)
                    SecureField("Token（至少 32 字符）", text: $token)
                        .privacySensitive()
                }
                Section("隧道") {
                    Picker("传输协议", selection: $transport) {
                        Text("QUIC").tag("quic")
                        Text("TCP · TLS 1.3").tag("tcp")
                        Text("TCP · 不加密").tag("tcp-plain")
                    }
                    Picker("混淆", selection: $obfs) {
                        Text("无").tag("none")
                        Text("Simple").tag("simple")
                        Text("Random").tag("random")
                    }
                    if transport == "tcp-plain" {
                        Text("此模式不加密。混淆不能保护通信内容。")
                            .foregroundColor(.orange)
                    }
                }
                Section("TLS 证书") {
                    TextField("服务器名称（可选）", text: $serverName)
                    Text("私有 CA：粘贴 PEM 证书；公开证书可留空。")
                        .font(.caption).foregroundColor(.secondary)
                    TextEditor(text: $ca)
                        .font(.system(.caption, design: .monospaced))
                        .frame(minHeight: 100)
                        .accessibilityLabel("CA 证书 PEM")
                }
                Section {
                    Button(vpn.busy ? "正在配置…" : "连接 VPN") {
                        vpn.connect(config: [
                            "server_addr": server.trimmingCharacters(in: .whitespacesAndNewlines),
                            "client_id": clientID.trimmingCharacters(in: .whitespacesAndNewlines),
                            "token": token.trimmingCharacters(in: .whitespacesAndNewlines),
                            "server_name": serverName.trimmingCharacters(in: .whitespacesAndNewlines),
                            "ca_pem": ca, "transport": transport, "obfs": obfs
                        ])
                    }
                    .disabled(vpn.active || vpn.busy || server.isEmpty || clientID.isEmpty || token.count < 32)
                    Button("断开", role: .destructive) { vpn.disconnect() }
                        .disabled(!vpn.active)
                } footer: {
                    Text("全局 IPv4 VPN，IPv6 被阻断。每台设备使用独立的客户端 ID。连接配置保存在本机 Keychain。")
                }
            }
            .textInputAutocapitalization(.never)
            .disableAutocorrection(true)
            .navigationTitle("Socks5Proxy")
        }
    }
}
