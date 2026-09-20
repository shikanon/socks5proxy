import Foundation
@preconcurrency import NetworkExtension
import Combine

@MainActor
final class VPNModel: ObservableObject {
    @Published var status = "未连接"
    @Published var active = false
    @Published var busy = false
    private var manager: NETunnelProviderManager?
    private var observer: NSObjectProtocol?
    private var timer: Timer?

    init() {
        observer = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange, object: nil, queue: .main
        ) { [weak self] _ in
            Task { @MainActor in self?.refresh() }
        }
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
            Task { @MainActor in
                guard let self, !self.busy else { return }
                self.manager = managers?.first(where: {
                    ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == self.providerID
                })
                if let error { self.status = error.localizedDescription }
                else { self.refresh() }
            }
        }
        timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.readCoreStatus() }
        }
    }

    private var providerID: String {
        (Bundle.main.bundleIdentifier ?? "com.shikanon.socks5proxy") + ".PacketTunnel"
    }

    func connect(config: [String: Any]) {
        guard !active, !busy else { return }
        busy = true
        status = "正在保存 VPN 配置…"
        do {
            let data = try JSONSerialization.data(withJSONObject: config)
            guard let json = String(data: data, encoding: .utf8) else { return }
            let reference = try ProfileStore.save(json)
            let manager = manager ?? NETunnelProviderManager()
            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = providerID
            proto.serverAddress = config["server_addr"] as? String
            proto.passwordReference = reference
            proto.disconnectOnSleep = false
            manager.protocolConfiguration = proto
            manager.localizedDescription = "Socks5Proxy"
            manager.isEnabled = true
            self.manager = manager
            manager.saveToPreferences { [weak self] error in
                Task { @MainActor in
                    guard let self else { return }
                    if let error { self.report(error); return }
                    manager.loadFromPreferences { [weak self] error in
                        Task { @MainActor in
                            guard let self else { return }
                            if let error { self.report(error); return }
                            do {
                                try manager.connection.startVPNTunnel()
                                self.busy = false
                                self.refresh()
                            } catch { self.report(error) }
                        }
                    }
                }
            }
        } catch { report(error) }
    }

    func disconnect() {
        manager?.connection.stopVPNTunnel()
        refresh()
    }

    private func report(_ error: Error) {
        busy = false
        status = error.localizedDescription
    }

    private func refresh() {
        let state = manager?.connection.status ?? .disconnected
        active = state == .connected || state == .connecting || state == .reasserting || state == .disconnecting
        switch state {
        case .connected: status = "已连接"
        case .connecting: status = "正在连接…"
        case .reasserting: status = "正在重连，流量保持阻断"
        case .disconnecting: status = "正在断开…"
        case .invalid: status = "请配置 VPN"
        default: status = "未连接"
        }
        if state == .disconnected, #available(iOS 16.0, *) {
            manager?.connection.fetchLastDisconnectError { [weak self] error in
                if let error {
                    Task { @MainActor in self?.status = error.localizedDescription }
                }
            }
        }
    }

    private func readCoreStatus() {
        guard manager?.connection.status == .connected,
              let session = manager?.connection as? NETunnelProviderSession else { return }
        try? session.sendProviderMessage(Data("status".utf8)) { [weak self] data in
            guard let data,
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return }
            let sent = (json["sent_bytes"] as? Int ?? 0) / 1024
            let received = (json["received_bytes"] as? Int ?? 0) / 1024
            Task { @MainActor in
                guard let self, self.manager?.connection.status == .connected else { return }
                self.status = "已连接 · ↑ \(sent) KB  ↓ \(received) KB"
            }
        }
    }

    deinit {
        if let observer { NotificationCenter.default.removeObserver(observer) }
        timer?.invalidate()
    }
}
