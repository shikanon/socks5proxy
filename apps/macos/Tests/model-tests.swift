import Foundation

@main
struct ModelTests {
    static func main() throws {
        let data = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))
        let baseline = try Adapter.decode(RuntimeSnapshot.self, data)
        precondition(baseline.title == "代理已就绪")
        precondition(baseline.groups.count == 2)
        precondition(baseline.groups[1].title == "海外 AI")
        precondition(baseline.groups[0].defaultServer == "backup")
        precondition(baseline.nodes[0].title == "节点 A")
        var dict = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        var groups = dict["groups"] as! [[String: Any]]
        groups[1]["selected_server"] = NSNull()
        dict["groups"] = groups
        let partial = try Adapter.decode(RuntimeSnapshot.self, JSONSerialization.data(withJSONObject: dict))
        precondition(partial.title == "部分通道可用")
        dict["ready"] = false
        let waiting = try Adapter.decode(RuntimeSnapshot.self, JSONSerialization.data(withJSONObject: dict))
        precondition(waiting.title == "通道未就绪")
        dict["running"] = false
        let stopped = try Adapter.decode(RuntimeSnapshot.self, JSONSerialization.data(withJSONObject: dict))
        precondition(stopped.title == "代理已停止")
        let error = Data("{\"ok\":false,\"message\":\"TEST_ONLY\"}".utf8)
        do {
            let _ = try Adapter.decode(RuntimeSnapshot.self, error)
            fatalError("Failed response accepted")
        } catch AdapterError.message(let text) { precondition(text == "TEST_ONLY") }
        print("Native models: 9 assertions passed")
    }
}
