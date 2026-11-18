import Foundation
import Combine
import Darwin

final class ProcessTimeout: @unchecked Sendable {
    private let lock = NSLock()
    private var timedOut = false
    func mark() { lock.lock(); timedOut = true; lock.unlock() }
    var value: Bool { lock.lock(); defer { lock.unlock() }; return timedOut }
}

struct ProxyNode: Decodable, Identifiable, Sendable {
    let id: String
    let endpoint: String
    let healthy: Bool
    var title: String { ["primary": "节点 A", "backup": "节点 B", "backup2": "节点 C"][id] ?? id }
}
struct ProbeNode: Decodable, Identifiable, Sendable {
    let id: String
    let state: String
    let responseMs: Double?
    let country: String?
    let egressState: String?
    let eligible: Bool?
    var label: String {
        switch state {
        case "reachable": "可达"
        case "unreachable": "不可达"
        case "policy_denied": "策略拒绝"
        default: "待确认"
        }
    }
}
struct DomainGroup: Decodable, Identifiable, Sendable {
    let id: String
    let defaultServer: String?
    let allowedServers: [String]
    let selectedServer: String?
    let selectedEndpoint: String
    let manual: String?
    let probing: Bool
    let nextProbe: Double?
    let nodes: [ProbeNode]
    let eligibleServers: [String]?
    let egressRequired: Bool?
    var title: String { ["ordinary": "普通网站", "overseas_ai": "海外 AI", "openai": "OpenAI / Codex", "claude": "Claude"][id] ?? id }
    var icon: String { ["ordinary": "globe", "overseas_ai": "sparkles", "openai": "sparkles", "claude": "bubble.left.and.text.bubble.right"][id] ?? "network" }
}
struct RuntimeSnapshot: Decodable, Sendable {
    let ok: Bool
    let installed: Bool
    let loaded: Bool
    let running: Bool
    let autostart: Bool
    let autostartVerified: Bool?
    let paused: Bool
    let fresh: Bool
    let ready: Bool
    let httpListening: Bool
    let pacListening: Bool
    let pacEnabled: Bool
    let doubaoDirect: Bool
    let ageSeconds: Double
    let nodes: [ProxyNode]
    let groups: [DomainGroup]
    let intervalSeconds: Int
    var partial: Bool { ready && groups.contains(where: { $0.selectedServer == nil }) }
    var title: String {
        if partial { return "部分通道可用" }
        if ready { return "代理已就绪" }
        if paused || !running { return "代理已停止" }
        if !fresh { return "状态待更新" }
        return "通道未就绪"
    }
}
struct BridgeReply: Decodable, Sendable {
    let ok: Bool
    let message: String?
    let host: String?
    let route: String?
    let reason: String?
    let match: String?
    let live: Bool?
}

enum AdapterError: Error, LocalizedError {
    case unavailable, invalidResponse, message(String)
    var errorDescription: String? {
        switch self {
        case .unavailable: "找不到客户端控制适配器。"
        case .invalidResponse: "控制接口未返回有效结果，请刷新状态。"
        case .message(let text): text
        }
    }
}

enum Adapter {
    static func pythonURL() -> URL {
        let bases = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/DoubaoWork/sandbox_runtime/bases")
        if let directories = try? FileManager.default.contentsOfDirectory(at: bases, includingPropertiesForKeys: nil) {
            for directory in directories.sorted(by: { $0.path < $1.path }) {
                let python = directory.appendingPathComponent("bin/python3")
                if FileManager.default.isExecutableFile(atPath: python.path) { return python }
            }
        }
        return URL(fileURLWithPath: "/usr/bin/python3")
    }
    static func call(root: String, action: String, extra: [String] = []) async throws -> Data {
        guard let script = Bundle.main.url(forResource: "bridge", withExtension: "py") else { throw AdapterError.unavailable }
        let args = [script.path, "--root", root, action] + extra
        return try await Task.detached(priority: .utility) {
            let process = Process()
            process.executableURL = pythonURL()
            process.arguments = args
            process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": FileManager.default.homeDirectoryForCurrentUser.path, "PYTHONDONTWRITEBYTECODE": "1", "LANG": "en_US.UTF-8"]
            let output = Pipe()
            process.standardOutput = output
            process.standardError = FileHandle.nullDevice
            process.standardInput = FileHandle.nullDevice
            try process.run()
            let timeout = ProcessTimeout()
            let budget: Double = action == "start" ? 125 : action == "stop" ? 60 : 20
            let timer = DispatchSource.makeTimerSource(queue: .global(qos: .utility))
            timer.schedule(deadline: .now() + budget)
            timer.setEventHandler {
                if process.isRunning {
                    timeout.mark()
                    process.terminate()
                    if process.isRunning { Darwin.kill(process.processIdentifier, SIGKILL) }
                }
            }
            timer.resume()
            let data = output.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            timer.cancel()
            guard !timeout.value else { throw AdapterError.message("本机状态读取超时；请检查文件访问权限后刷新。写操作可能已生效，不要重复执行。") }
            guard process.terminationStatus == 0, data.count <= 2_097_152 else { throw AdapterError.invalidResponse }
            return data
        }.value
    }
    static func decode<T: Decodable>(_ type: T.Type, _ data: Data) throws -> T {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        let reply = try decoder.decode(BridgeReply.self, from: data)
        guard reply.ok else { throw AdapterError.message(reply.message ?? "操作未完成。") }
        return try decoder.decode(type, from: data)
    }
}

@MainActor
final class ProxyStore: ObservableObject {
    @Published var snapshot: RuntimeSnapshot?
    @Published var error: String?
    @Published var operationError: String?
    @Published var notice: String?
    @Published var busy = false
    @Published var refreshing = false
    @Published var projectPath: String
    @Published var queryResult: BridgeReply?
    let demo: Bool
    private var poll: Task<Void, Never>?

    init() {
        let args = CommandLine.arguments
        demo = args.contains("--demo")
        if let index = args.firstIndex(of: "--project"), args.indices.contains(index + 1) {
            projectPath = args[index + 1]
        } else {
            projectPath = UserDefaults.standard.string(forKey: "projectPath") ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Documents/socks5proxy").path
        }
        poll = Task { [weak self] in
            while !Task.isCancelled {
                await self?.refresh()
                try? await Task.sleep(for: .seconds(4))
            }
        }
    }
    func refresh() async {
        guard !refreshing else { return }
        refreshing = true
        defer { refreshing = false }
        do {
            let data: Data
            if demo, let file = Bundle.main.url(forResource: "demo", withExtension: "json") {
                data = try Data(contentsOf: file)
            } else {
                data = try await NativeStatus.read(root: projectPath)
            }
            snapshot = try Adapter.decode(RuntimeSnapshot.self, data)
            error = nil
        } catch {
            snapshot = nil
            self.error = error.localizedDescription
        }
    }
    func perform(_ action: String, group: String? = nil, server: String? = nil) async {
        guard !busy else { return }
        guard !demo else { notice = "演示模式不会执行代理操作。"; return }
        busy = true; notice = nil; operationError = nil
        defer { busy = false }
        var args: [String] = []
        if let group { args += ["--group", group] }
        if let server { args += ["--server", server] }
        do {
            let data = try await Adapter.call(root: projectPath, action: action, extra: args)
            let result = try Adapter.decode(BridgeReply.self, data)
            notice = result.message
        } catch { self.operationError = error.localizedDescription }
        await refresh()
    }
    func query(_ host: String) async {
        guard !busy else { return }
        guard !demo else { notice = "演示模式不查询真实网络。"; return }
        busy = true; queryResult = nil; operationError = nil
        defer { busy = false }
        do {
            let data = try await Adapter.call(root: projectPath, action: "query", extra: ["--host", host])
            queryResult = try Adapter.decode(BridgeReply.self, data)
        } catch { self.operationError = error.localizedDescription }
    }
    func setProject(_ url: URL) {
        projectPath = url.standardizedFileURL.path
        UserDefaults.standard.set(projectPath, forKey: "projectPath")
        snapshot = nil; queryResult = nil
        Task { await refresh() }
    }
    func nodeTitle(_ id: String?) -> String {
        guard let id else { return "暂无可用节点" }
        return snapshot?.nodes.first(where: { $0.id == id })?.title ?? id
    }
}
