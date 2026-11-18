import SwiftUI
import AppKit

@MainActor
final class MainWindowRegistry: NSObject, NSWindowDelegate {
    static let shared = MainWindowRegistry()
    private var window: NSWindow?
    private var pendingShow = false
    func capture(_ value: NSWindow) {
        guard window !== value else { return }
        window = value
        value.delegate = self
        value.isReleasedWhenClosed = false
        if pendingShow { pendingShow = false; show() }
    }
    func show() {
        guard let window else { pendingShow = true; return }
        if window.isMiniaturized { window.deminiaturize(nil) }
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }
    func windowShouldClose(_ sender: NSWindow) -> Bool {
        // Close means hide the one retained window. Menu/Dock/relaunch brings it back.
        sender.orderOut(nil)
        return false
    }
}

struct MainWindowCapture: NSViewRepresentable {
    final class CaptureView: NSView {
        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            if let window { MainWindowRegistry.shared.capture(window) }
        }
    }
    func makeNSView(context: Context) -> CaptureView { CaptureView() }
    func updateNSView(_ nsView: CaptureView, context: Context) {
        if let window = nsView.window { MainWindowRegistry.shared.capture(window) }
    }
}
