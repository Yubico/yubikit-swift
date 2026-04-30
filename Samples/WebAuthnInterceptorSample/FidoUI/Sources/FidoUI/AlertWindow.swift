import SwiftUI

#if os(iOS)
import UIKit
#elseif os(macOS)
import AppKit
#endif

/// Per-ceremony alert window. Opens when a FidoUI entry point starts, closes
/// when it returns. Content-driven height — the macOS path observes the
/// hosted SwiftUI view's reported size and animates the `NSPanel` frame;
/// iOS is naturally content-driven because the panel is centered inside a
/// full-screen window.
extension FidoUI {
    @MainActor
    final class AlertWindow {
        #if os(iOS)
        private var window: UIWindow?
        #elseif os(macOS)
        private var panel: NSPanel?
        #endif

        func present(model: PanelModel) {
            #if os(iOS)
            presentIOS(model: model)
            #elseif os(macOS)
            presentMac(model: model)
            #endif
        }

        func dismiss() {
            #if os(iOS)
            window?.isHidden = true
            window = nil
            #elseif os(macOS)
            panel?.close()
            panel = nil
            #endif
        }
    }
}

/// Material card used by the alert window — production hosts and previews share
/// this so chrome (corner radius, shadow, material) stays in one place.
struct AlertBody<Content: View>: View {
    let content: Content

    init(@ViewBuilder content: () -> Content) {
        self.content = content()
    }

    var body: some View {
        content
            .background(.regularMaterial)
            .clipShape(.rect(cornerRadius: 14))
            .shadow(color: .black.opacity(0.25), radius: 20, y: 8)
    }
}

extension View {
    /// Wraps a panel in the same alert chrome the runtime hosts, so previews
    /// render the production view tree (minus the OS-level host window).
    /// iOS adds the dim backdrop; macOS adds the shadow padding the
    /// transparent `NSPanel` needs.
    func fidoAlertChrome() -> some View {
        #if os(iOS)
        AlertRoot { self }
        #elseif os(macOS)
        AlertBody { self }.padding(32)
        #endif
    }
}

#if os(iOS)
extension FidoUI.AlertWindow {
    private func presentIOS(model: FidoUI.PanelModel) {
        // Idempotent: a second `present` before `dismiss` would orphan the
        // first `UIWindow` until the next `dismiss` released only the new
        // one. Mirrors the macOS guard.
        guard window == nil else { return }
        guard let scene = Self.activeWindowScene() else {
            // Without a hostable scene the alert window can't show — the
            // ceremony will appear to hang. Log instead of failing silently.
            fidoLog("AlertWindow", "No active window scene; alert will not present.")
            return
        }
        let hosting = UIHostingController(
            rootView: IOSAlertRoot(model: model)
        )
        hosting.view.backgroundColor = .clear
        let window = UIWindow(windowScene: scene)
        window.rootViewController = hosting
        window.windowLevel = .alert
        window.backgroundColor = .clear
        window.makeKeyAndVisible()
        self.window = window
    }

    private static func activeWindowScene() -> UIWindowScene? {
        let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
        return scenes.first(where: { $0.activationState == .foregroundActive }) ?? scenes.first
    }
}

struct AlertRoot<Content: View>: View {
    let content: Content

    init(@ViewBuilder content: () -> Content) {
        self.content = content()
    }

    var body: some View {
        ZStack {
            Color.black.opacity(0.35).ignoresSafeArea()
            AlertBody { content }
        }
    }
}

/// Hosts the iOS alert content but only renders the dim backdrop + panel once
/// `model.isPresented` flips true. Mirror of `AlertContent`'s gate on macOS:
/// a fast session-acquire that returns before the panel install never flashes.
private struct IOSAlertRoot: View {
    let model: FidoUI.PanelModel

    var body: some View {
        if model.isPresented {
            AlertRoot { FidoUI.PanelView(model: model) }
        } else {
            Color.clear
        }
    }
}
#endif

#if os(macOS)
/// Borderless NSPanel won't become key by default — override so text fields
/// (PIN entry) receive keyboard input.
private final class AlertPanel: NSPanel {
    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { false }
}

extension FidoUI.AlertWindow {
    private func presentMac(model: FidoUI.PanelModel) {
        // Idempotent: a second `present` before `dismiss` would orphan the
        // first `NSPanel` (no nil check otherwise). Today FidoUI always
        // pairs present/dismiss via `withAlertWindow`, but keep the guard
        // so a stray double-call is a no-op rather than a leak.
        guard panel == nil else { return }
        let panel = AlertPanel(
            contentRect: NSRect(x: 0, y: 0, width: 464, height: 240),
            styleMask: [.borderless, .nonactivatingPanel],
            backing: .buffered,
            defer: false
        )
        panel.isOpaque = false
        panel.backgroundColor = .clear
        panel.hasShadow = false
        panel.level = .modalPanel
        panel.hidesOnDeactivate = false
        panel.isMovableByWindowBackground = false

        let content = AlertContent(model: model) { [weak self, weak panel] size in
            guard let self, let panel, size.width > 0, size.height > 0 else { return }
            self.resize(panel: panel, to: size)
        }
        panel.contentViewController = NSHostingController(rootView: content)
        panel.center()
        panel.makeKeyAndOrderFront(nil)
        self.panel = panel
    }

    private func resize(panel: NSPanel, to size: CGSize) {
        let current = panel.frame
        guard size != current.size else { return }
        // `panel.center()` placed the top edge at Apple's conventional 1/3
        // from the screen top. Anchor the top edge through every resize so
        // the panel stays where macOS dialogs are expected to be (rather
        // than drifting to vertical center as content grows).
        let newOrigin = NSPoint(
            x: current.midX - size.width / 2,
            y: current.maxY - size.height
        )
        panel.setFrame(NSRect(origin: newOrigin, size: size), display: true)
    }
}

/// macOS wraps `AlertBody` in padding so the SwiftUI shadow has room to render
/// inside the (transparent) window bounds. The outer size is reported back to
/// the `AlertWindow` so the `NSPanel` frame follows content height. While
/// `model.isPresented` is false the content is fully transparent so a fast
/// session-acquire returning before the panel install never flashes a panel.
private struct AlertContent: View {
    let model: FidoUI.PanelModel
    let onSize: @MainActor (CGSize) -> Void

    var body: some View {
        if model.isPresented {
            AlertBody { FidoUI.PanelView(model: model) }
                .padding(32)
                .onGeometryChange(for: CGSize.self) {
                    $0.size
                } action: {
                    onSize($0)
                }
        } else {
            Color.clear
        }
    }
}
#endif
