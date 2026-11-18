import Foundation

@main
struct NativeReadTest {
    static func main() async throws {
        let root = CommandLine.arguments[1]
        let data = try await NativeStatus.read(root: root)
        let result = try Adapter.decode(RuntimeSnapshot.self, data)
        precondition(result.groups.map(\.id) == ["ordinary", "overseas_ai"])
        precondition(result.groups[0].defaultServer == "backup")
        precondition(result.groups[1].defaultServer == "primary")
        precondition(result.groups[1].egressRequired == true)
        precondition(!NativeStatus.processMatches(pid: Int(ProcessInfo.processInfo.processIdentifier), expected: ["/bin/not-the-current-program"]))
        precondition(!NativeStatus.processMatches(pid: -1, expected: ["/bin/example"]))
        precondition(result.doubaoDirect)
        print("Native read: 7 live assertions passed; application access not verified")
    }
}
