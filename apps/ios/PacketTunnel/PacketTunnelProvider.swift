import Foundation
import NetworkExtension
import TunnelCore
import Darwin

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let lock = NSLock()
    private var core: MobileClient?
    private var stopped = false
    private var startCompletion: ((Error?) -> Void)?
    private let monitorQueue = DispatchQueue(label: "vpn.status")
    private var monitor: DispatchSourceTimer?

    override func startTunnel(options: [String: NSObject]?,
                              completionHandler: @escaping (Error?) -> Void) {
        lock.lock()
        stopped = false
        startCompletion = completionHandler
        lock.unlock()
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            do {
                guard let proto = self.protocolConfiguration as? NETunnelProviderProtocol,
                      let reference = proto.passwordReference else {
                    throw self.failure("缺少 VPN 配置，请从主应用重新连接")
                }
                let json = try ProfileStore.load(reference: reference)
                var creationError: NSError?
                guard let client = MobileNewClient(json, nil, &creationError) else {
                    throw creationError ?? self.failure("无法创建隧道")
                }
                self.lock.lock()
                if self.stopped {
                    self.lock.unlock()
                    try? client.close()
                    return
                }
                self.core = client
                self.lock.unlock()
                // gomobile's nonnullable String return keeps NSError explicit.
                var connectError: NSError?
                let response = client.connect(&connectError)
                if let connectError { throw connectError }
                guard let data = response.data(using: .utf8),
                      let p = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                      let endpoint = p["endpoint_ipv4"] as? String,
                      let address = p["client_ipv4"] as? String,
                      let dns = p["dns_ipv4"] as? String,
                      let mtu = p["mtu"] as? Int else {
                    throw self.failure("服务端返回了无效网络配置")
                }
                let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: endpoint)
                let ipv4 = NEIPv4Settings(addresses: [address], subnetMasks: ["255.255.255.255"])
                ipv4.includedRoutes = [NEIPv4Route.default()]
                // Provider-owned sockets bypass the tunnel; no endpoint exclusion
                // is needed, so app traffic to that IP also follows the VPN.
                settings.ipv4Settings = ipv4
                // Capture IPv6 and discard it in the packet loop, since the wire
                // protocol only supports IPv4. This prevents an IPv6 bypass.
                let ipv6 = NEIPv6Settings(addresses: ["fd00:5:5::2"], networkPrefixLengths: [128])
                ipv6.includedRoutes = [NEIPv6Route.default()]
                settings.ipv6Settings = ipv6
                let dnsSettings = NEDNSSettings(servers: [dns])
                dnsSettings.matchDomains = [""]
                settings.dnsSettings = dnsSettings
                settings.mtu = NSNumber(value: mtu)
                self.lock.lock()
                let wasStopped = self.stopped
                self.lock.unlock()
                if wasStopped { return }
                self.setTunnelNetworkSettings(settings) { [weak self] error in
                    guard let self else { return }
                    if let error { self.terminate(error); return }
                    self.lock.lock()
                    let stopped = self.stopped
                    self.lock.unlock()
                    if stopped { return }
                    do {
                        try client.start()
                        self.readFromOS(client)
                        self.writeToOS(client)
                        self.startMonitor(client)
                        self.finishStart(nil)
                    } catch { self.terminate(error) }
                }
            } catch { self.terminate(error) }
        }
    }

    private func readFromOS(_ client: MobileClient) {
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self, self.isRunning else { return }
            do {
                for (packet, family) in zip(packets, protocols) where family.int32Value == AF_INET {
                    try client.writePacket(packet)
                }
                self.readFromOS(client)
            } catch { self.terminate(error) }
        }
    }

    private func writeToOS(_ client: MobileClient) {
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            do {
                while self.isRunning {
                    let packet = try client.readPacket()
                    guard self.packetFlow.writePackets([packet], withProtocols: [NSNumber(value: AF_INET)]) else {
                        throw self.failure("无法向系统写入 VPN 数据包")
                    }
                }
            } catch {
                if self.isRunning { self.terminate(error) }
            }
        }
    }

    private var isRunning: Bool {
        lock.lock()
        defer { lock.unlock() }
        return !stopped
    }

    private func startMonitor(_ client: MobileClient) {
        monitorQueue.async { [weak self] in
            guard let self, self.isRunning else { return }
            let timer = DispatchSource.makeTimerSource(queue: self.monitorQueue)
            timer.schedule(deadline: .now(), repeating: .seconds(2))
            timer.setEventHandler { [weak self] in
                guard let self, self.isRunning,
                      let raw = client.status().data(using: .utf8),
                      let status = try? JSONSerialization.jsonObject(with: raw) as? [String: Any] else { return }
                let state = status["state"] as? String
                self.reasserting = state == "reconnecting"
                if state == "error" || state == "closed" {
                    self.terminate(self.failure(status["error"] as? String ?? "隧道已停止"))
                }
            }
            self.monitor = timer
            timer.resume()
        }
    }

    private func finishStart(_ error: Error?) {
        lock.lock()
        let completion = startCompletion
        startCompletion = nil
        lock.unlock()
        completion?(error)
    }

    private func terminate(_ error: Error) {
        lock.lock()
        if stopped { lock.unlock(); return }
        stopped = true
        let client = core
        core = nil
        lock.unlock()
        try? client?.close()
        monitorQueue.async { [weak self] in
            self?.monitor?.cancel()
            self?.monitor = nil
        }
        finishStart(error)
        cancelTunnelWithError(error)
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        lock.lock()
        stopped = true
        let client = core
        core = nil
        lock.unlock()
        try? client?.close()
        monitorQueue.async { [weak self] in
            self?.monitor?.cancel()
            self?.monitor = nil
        }
        finishStart(failure("连接已取消"))
        completionHandler()
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        lock.lock()
        let status = core?.status() ?? "{\"state\":\"closed\"}"
        lock.unlock()
        completionHandler?(status.data(using: .utf8))
    }

    private func failure(_ message: String) -> NSError {
        NSError(domain: "Socks5Proxy", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
}
