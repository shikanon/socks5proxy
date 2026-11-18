import Foundation
import AppKit
import Darwin

/// Process-lifetime advisory lock. Never unlink the inode while it may be held.
final class InstanceLock {
    private var descriptor: Int32 = -1
    private(set) var ownerPID: pid_t?

    func acquire(at file: URL) throws -> Bool {
        guard descriptor < 0 else { return true }
        let fd = Darwin.open(file.path, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, S_IRUSR | S_IWUSR)
        guard fd >= 0 else { throw CocoaError(.fileReadNoPermission) }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_uid == getuid(),
              (info.st_mode & S_IFMT) == S_IFREG, info.st_nlink == 1,
              fchmod(fd, S_IRUSR | S_IWUSR) == 0 else {
            close(fd); throw CocoaError(.fileReadNoPermission)
        }
        guard flock(fd, LOCK_EX | LOCK_NB) == 0 else {
            let reason = errno
            var bytes = [UInt8](repeating: 0, count: 32)
            let size = pread(fd, &bytes, bytes.count, 0)
            if size > 0 { ownerPID = String(decoding: bytes.prefix(Int(size)), as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines).flatMapPID }
            close(fd)
            if reason == EWOULDBLOCK || reason == EAGAIN { return false }
            throw CocoaError(.fileReadUnknown)
        }
        let record = Array("\(getpid())\n".utf8)
        guard ftruncate(fd, 0) == 0, record.withUnsafeBytes({ pwrite(fd, $0.baseAddress, record.count, 0) }) == record.count else {
            close(fd); throw CocoaError(.fileWriteUnknown)
        }
        descriptor = fd; ownerPID = getpid()
        return true
    }
    func release() {
        if descriptor >= 0 { close(descriptor); descriptor = -1 }
    }
    deinit { release() }
}

private extension String {
    var flatMapPID: pid_t? { Int32(self).flatMap { $0 > 0 ? $0 : nil } }
}

@MainActor
enum SingleInstance {
    static let bundleID = "com.shikanon.socks5proxy.mac"
    static let wakeName = Notification.Name("com.shikanon.socks5proxy.mac.show-window")
    static let localWake = Notification.Name("Socks5ProxyShowMainWindow")
    private static let lock = InstanceLock()
    private static var observer: NSObjectProtocol?

    static func bootstrap() {
        do {
            let directory = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/Socks5Proxy")
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            var info = stat()
            guard lstat(directory.path, &info) == 0, info.st_uid == getuid(), (info.st_mode & S_IFMT) == S_IFDIR else {
                throw CocoaError(.fileReadNoPermission)
            }
            guard chmod(directory.path, S_IRWXU) == 0 else { throw CocoaError(.fileReadNoPermission) }
            if try lock.acquire(at: directory.appendingPathComponent("client.lock")) {
                // Older builds did not take this lock. Never create another UI beside one.
                let older = NSRunningApplication.runningApplications(withBundleIdentifier: bundleID)
                    .filter { app in
                        guard app.processIdentifier != getpid(), !app.isTerminated,
                              let url = app.bundleURL,
                              let data = try? Data(contentsOf: url.appendingPathComponent("Contents/Info.plist")),
                              let info = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else { return false }
                        return info["SPSingleInstanceVersion"] as? Int != 1
                    }
                    .sorted { $0.processIdentifier < $1.processIdentifier }
                if let app = older.first {
                    app.activate(options: [.activateAllWindows])
                    exit(0)
                }
                observer = DistributedNotificationCenter.default().addObserver(forName: wakeName, object: String(getuid()), queue: .main) { _ in
                    Task { @MainActor in
                        MainWindowRegistry.shared.show()
                        NotificationCenter.default.post(name: localWake, object: nil)
                    }
                }
                return
            }
            // Fixed wake signal, no paths, arguments, account data or network settings.
            // A brief retry covers simultaneous starts before the winner has a window.
            for _ in 0..<15 {
                DistributedNotificationCenter.default().postNotificationName(wakeName, object: String(getuid()), userInfo: nil, deliverImmediately: true)
                if let pid = lock.ownerPID, let app = NSRunningApplication(processIdentifier: pid), app.bundleIdentifier == bundleID {
                    app.activate(options: [.activateAllWindows])
                }
                usleep(100_000)
            }
            exit(0)
        } catch {
            let alert = NSAlert()
            alert.messageText = "无法确认客户端单实例状态"
            alert.informativeText = "未启动第二个客户端，也未修改代理。请检查本机应用数据目录的访问权限。"
            alert.runModal()
            exit(1)
        }
    }
}

@MainActor
final class ClientAppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        MainWindowRegistry.shared.show()
        NotificationCenter.default.post(name: SingleInstance.localWake, object: nil)
        return true
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
}
