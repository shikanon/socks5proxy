import Foundation
import Darwin
import CFNetwork

// Read-only native state: no Python process, shell, credentials or target website request.
enum NativeStatus {
    static func object(_ url: URL) throws -> [String: Any] {
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        guard let size = attributes[.size] as? NSNumber, size.intValue <= 2_097_152 else { throw AdapterError.invalidResponse }
        let data = try Data(contentsOf: url)
        guard let dict = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw AdapterError.invalidResponse }
        return dict
    }
    static func processMatches(pid: Int, expected: [String]) -> Bool {
        guard pid > 0, !expected.isEmpty, kill(pid_t(pid), 0) == 0 else { return false }
        var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, Int32(pid)]
        var size = 0
        guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > 4, size <= 1_048_576 else { return false }
        var bytes = [UInt8](repeating: 0, count: size)
        guard sysctl(&mib, 3, &bytes, &size, nil, 0) == 0 else { return false }
        let argc = bytes.withUnsafeBytes { $0.loadUnaligned(as: Int32.self) }
        guard argc > 0 && argc < 128 else { return false }
        var index = 4
        while index < size && bytes[index] != 0 { index += 1 }
        while index < size && bytes[index] == 0 { index += 1 }
        var arguments: [String] = []
        for _ in 0..<Int(argc) {
            let start = index
            while index < size && bytes[index] != 0 { index += 1 }
            guard index < size else { return false }
            arguments.append(String(decoding: bytes[start..<index], as: UTF8.self)); index += 1
        }
        // Compare only executable/script/runtime argv; never decode or display environment.
        guard arguments.count >= expected.count else { return false }
        return zip(arguments, expected).allSatisfy { actual, wanted in
            if wanted.hasPrefix("/") { return URL(fileURLWithPath: actual).resolvingSymlinksInPath().path == URL(fileURLWithPath: wanted).resolvingSymlinksInPath().path }
            return actual == wanted
        }
    }
    static func read(root: String) async throws -> Data {
        let local = try await Task.detached(priority: .utility) { () throws -> [String: Any] in
            let base = URL(fileURLWithPath: root).resolvingSymlinksInPath().appendingPathComponent("dist/overseas-proxy")
            let cfg = try object(base.appendingPathComponent("multi-server.json"))
            let state = try object(base.appendingPathComponent("multi-state.json"))
            let home = FileManager.default.homeDirectoryForCurrentUser
            let plist = home.appendingPathComponent("Library/LaunchAgents/com.shikanon.socks5proxy.community.plist")
            let installed = FileManager.default.fileExists(atPath: plist.path)
            var onLoad = false
            var expectedArguments: [String] = []
            if installed {
                guard let job = try PropertyListSerialization.propertyList(from: Data(contentsOf: plist), format: nil) as? [String: Any],
                      let argv = job["ProgramArguments"] as? [String], let pos = argv.firstIndex(of: "--runtime"), argv.indices.contains(pos+1),
                      URL(fileURLWithPath: argv[pos+1]).resolvingSymlinksInPath().path == base.path else {
                    throw AdapterError.message("启动项属于另一个运行目录，未执行任何代理操作。")
                }
                onLoad = job["RunAtLoad"] as? Bool == true
                expectedArguments = argv
            }
            let managerPID = state["manager_pid"] as? Int ?? 0
            let running = installed && processMatches(pid: managerPID, expected: expectedArguments)
            let delta = Date().timeIntervalSince1970 - (state["updated_at"] as? Double ?? 0)
            let fresh = delta >= 0 && delta < 8 && running
            let disabledFile = home.appendingPathComponent("Library/Preferences/com.apple.xpc.launchd/disabled.\(getuid()).plist")
            let disabled = (try? Data(contentsOf: disabledFile)).flatMap { try? PropertyListSerialization.propertyList(from: $0, format: nil) as? [String: Bool] }
            let enabled = disabled.map { $0["com.shikanon.socks5proxy.community"] != true }
            let routes = cfg["domain_routes"] as? [String: Any] ?? [:]
            let groupCfg = routes["groups"] as? [String: [String: Any]] ?? [:]
            let domainState = state["domain_routes"] as? [String: Any] ?? [:]
            let groupState = domainState["groups"] as? [String: [String: Any]] ?? [:]
            let health = state["servers"] as? [String: [String: Any]] ?? [:]
            let egress = (domainState["egress_verification"] as? [String: Any])?["nodes"] as? [String: [String: Any]] ?? [:]
            let servers = cfg["servers"] as? [[String: Any]] ?? []
            let nodes: [[String: Any]] = servers.map { server in
                let name = server["name"] as? String ?? ""
                return ["id": name, "endpoint": server["endpoint"] as? String ?? "", "healthy": fresh && health[name]?["healthy"] as? Bool == true]
            }
            let groups: [[String: Any]] = groupCfg.keys.sorted { a, b in a == "ordinary" && b != "ordinary" || (a != "ordinary" && b != "ordinary" && a < b) }.map { name in
                let c = groupCfg[name] ?? [:], s = groupState[name] ?? [:]
                let probe = s["nodes"] as? [String: [String: Any]] ?? [:]
                let required = (routes["egress_policy"] as? [String: Any])?["group"] as? String == name
                let stats: [[String: Any]] = nodes.map { node in
                    let id = node["id"] as? String ?? "", p = probe[id] ?? [:], e = egress[id] ?? [:]
                    let age = Date().timeIntervalSince1970 - (e["checked_at"] as? Double ?? 0)
                    let recent = fresh && age >= 0 && age < 3600
                    let country = e["country"] as? String
                    return ["id": id, "state": fresh ? p["state"] as? String ?? "unknown" : "unknown",
                            "response_ms": fresh ? p["median_response_ms"] ?? NSNull() : NSNull(),
                            "country": recent ? country as Any? ?? NSNull() : NSNull(),
                            "egress_state": recent ? e["state"] as? String ?? "unknown" : "unknown",
                            "eligible": !required || recent && e["eligible"] as? Bool == true && !["HK", "MO"].contains(country ?? "")]
                }
                return ["id": name, "default_server": c["default_server"] ?? NSNull(), "allowed_servers": c["allowed_servers"] ?? [],
                        "eligible_servers": stats.filter { $0["eligible"] as? Bool == true }.compactMap { $0["id"] as? String },
                        "egress_required": required, "selected_server": fresh ? s["preferred_available"] ?? NSNull() : NSNull(),
                        "selected_endpoint": fresh ? s["preferred_endpoint"] as? String ?? "" : "", "manual": s["manual_preference"] ?? NSNull(),
                        "probing": fresh && s["running"] as? Bool == true, "next_probe": s["next_probe_at"] ?? NSNull(), "nodes": stats]
            }
            return ["ok": true, "installed": installed, "loaded": running, "running": running,
                    "autostart": onLoad && enabled == true, "autostart_verified": enabled != nil,
                    "paused": FileManager.default.fileExists(atPath: base.appendingPathComponent("multi-paused").path),
                    "fresh": fresh, "ready": fresh && state["ready"] as? Bool == true,
                    "http_listening": fresh && state["http_front_pid"] as? Int == state["manager_pid"] as? Int,
                    "pac_listening": false, "pac_enabled": false, "doubao_direct": false,
                    "age_seconds": max(0, delta), "nodes": nodes, "groups": groups, "interval_seconds": routes["interval_seconds"] ?? 1800]
        }.value
        var result = local
        let proxies = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any] ?? [:]
        let enabled = (proxies["ProxyAutoConfigEnable"] as? NSNumber)?.boolValue == true && proxies["ProxyAutoConfigURLString"] as? String == "http://127.0.0.1:8090/proxy.pac"
        result["pac_enabled"] = enabled
        let configuration = URLSessionConfiguration.ephemeral
        configuration.connectionProxyDictionary = [:]
        configuration.timeoutIntervalForRequest = 2
        configuration.timeoutIntervalForResource = 2
        let session = URLSession(configuration: configuration)
        defer { session.invalidateAndCancel() }
        if let (data, response) = try? await session.data(from: URL(string: "http://127.0.0.1:8090/proxy.pac")!), (response as? HTTPURLResponse)?.statusCode == 200, data.count <= 2_097_152 {
            result["pac_listening"] = true
            let base = URL(fileURLWithPath: root).appendingPathComponent("dist/overseas-proxy/community-pac")
            if let community = try? Data(contentsOf: base.appendingPathComponent("proxy.pac")), let wrapper = try? Data(contentsOf: base.appendingPathComponent("direct-first.js")), data == community + Data([10]) + wrapper {
                let text = String(data: wrapper, encoding: .utf8) ?? ""
                result["doubao_direct"] = ["doubao.com", "doubaowork.com", "bytedance.com", "feishu.cn", "larkoffice.com"].allSatisfy { text.contains("\"\($0)\"") }
            }
        }
        result["ready"] = result["ready"] as? Bool == true && result["http_listening"] as? Bool == true && result["pac_listening"] as? Bool == true && enabled
        return try JSONSerialization.data(withJSONObject: result)
    }
}
