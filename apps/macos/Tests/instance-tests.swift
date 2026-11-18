import Foundation
import Darwin

@main
struct InstanceTests {
    static func main() throws {
        let args = CommandLine.arguments
        if args.count == 4 && args[1] == "--hold" {
            let lock = InstanceLock()
            if try lock.acquire(at: URL(fileURLWithPath: args[2])) {
                print("OWNER"); fflush(stdout); usleep(UInt32(args[3])!); return
            }
            print("DUPLICATE"); return
        }
        let directory = URL(fileURLWithPath: args[1])
        let path = directory.appendingPathComponent("isolated.lock")
        let first = InstanceLock(), second = InstanceLock()
        func acquire(_ lock: InstanceLock, _ url: URL) -> Bool { try! lock.acquire(at: url) }
        precondition(acquire(first, path))
        precondition(acquire(first, path))
        precondition(!acquire(second, path))
        precondition(second.ownerPID == getpid())
        first.release()
        precondition(acquire(second, path))
        second.release()
        try "999999\n".write(to: path, atomically: false, encoding: .utf8)
        let stale = InstanceLock()
        precondition(acquire(stale, path))
        stale.release()
        let link = directory.appendingPathComponent("symlink.lock")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: path)
        do { _ = try InstanceLock().acquire(at: link); fatalError("Symlink accepted") } catch { }
        let hard = directory.appendingPathComponent("hardlink.lock")
        try FileManager.default.linkItem(at: path, to: hard)
        do { _ = try InstanceLock().acquire(at: hard); fatalError("Hardlink accepted") } catch { }
        print("Instance lock: 8 assertions passed")
    }
}
