import SwiftUI

#if os(iOS)
import UIKit
#elseif os(macOS)
import AppKit
#endif

/// Per-ceremony alert window. Content-driven height: macOS observes the
/// hosted view's reported size and resizes the NSPanel; iOS is naturally
/// content-driven inside a full-screen window.
extension FidoUI {
    @MainActor
    final class AlertWindow {
        #if os(iOS)
        private var window: UIWindow?
        private weak var previousKeyWindow: UIWindow?
        #elseif os(macOS)
        private var panel: NSPanel?
        private var hasSizedPanel = false
        #endif

        func present(model: PanelModel, anchor: PresentationAnchor?) throws(FidoUI.Error) {
            guard let anchor else { throw .presentationUnavailable }
            #if os(iOS)
            guard let scene = anchor.windowScene, scene.activationState == .foregroundActive,
                !anchor.isHidden
            else { throw .presentationUnavailable }
            presentIOS(model: model, anchor: anchor, scene: scene)
            #elseif os(macOS)
            guard anchor.isVisible, !anchor.isMiniaturized else { throw .presentationUnavailable }
            presentMac(model: model, anchor: anchor)
            #endif
        }

        func dismiss() {
            #if os(iOS)
            let restoreKeyWindow = window?.isKeyWindow == true
            window?.isHidden = true
            window = nil
            if restoreKeyWindow, let previousKeyWindow, !previousKeyWindow.isHidden {
                previousKeyWindow.makeKey()
            }
            previousKeyWindow = nil
            #elseif os(macOS)
            let parent = panel?.parent
            let restoreKeyWindow = panel?.isKeyWindow == true
            if let panel { parent?.removeChildWindow(panel) }
            panel?.close()
            panel = nil
            if restoreKeyWindow, let parent, parent.isVisible {
                parent.makeKey()
            }
            #endif
        }
    }
}

private struct AlertBody<Content: View>: View {
    private let content: Content

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
    /// Production chrome reused by `#Preview` so previews render against
    /// the same view tree as the runtime.
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
    private func presentIOS(model: FidoUI.PanelModel, anchor: UIWindow, scene: UIWindowScene) {
        guard window == nil else { return }
        previousKeyWindow = scene.keyWindow ?? anchor
        let hosting = UIHostingController(
            rootView: IOSAlertRoot(model: model)
        )
        hosting.view.backgroundColor = .clear
        let window = UIWindow(windowScene: scene)
        window.rootViewController = hosting
        // Stay above the host app while allowing the keyboard above this window.
        window.windowLevel = .normal + 1
        window.backgroundColor = .clear
        window.makeKeyAndVisible()
        self.window = window
    }
}

private struct AlertRoot<Content: View>: View {
    private let content: Content
    @State private var contentHeight: CGFloat?

    init(@ViewBuilder content: () -> Content) {
        self.content = content()
    }

    var body: some View {
        ZStack {
            Color.black.opacity(0.35).ignoresSafeArea()
            AlertBody {
                ScrollView {
                    content
                        .onGeometryChange(for: CGFloat.self) {
                            $0.size.height
                        } action: {
                            contentHeight = $0
                        }
                }
                .scrollBounceBehavior(.basedOnSize)
                .frame(maxHeight: contentHeight)
            }
            .frame(maxWidth: 400)
            .padding(16)
        }
    }
}

/// Renders nothing until `model.isPresented` flips true — a fast
/// session-acquire that returns before the panel install never flashes.
private struct IOSAlertRoot: View {
    let model: FidoUI.PanelModel

    var body: some View {
        if model.isPresented {
            if model.isNFCActive {
                Color.black.opacity(0.35).ignoresSafeArea()
            } else {
                AlertRoot { FidoUI.PanelView(model: model) }
            }
        } else {
            Color.clear
        }
    }
}
#endif

#if os(macOS)
/// Borderless NSPanel won't become key by default — override so the PIN
/// field receives keyboard input.
private final class AlertPanel: NSPanel {
    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { false }
}

extension FidoUI.AlertWindow {
    private func presentMac(model: FidoUI.PanelModel, anchor: NSWindow) {
        guard panel == nil else { return }
        hasSizedPanel = false
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
        let parentFrame = anchor.frame
        panel.setFrameOrigin(
            NSPoint(x: parentFrame.midX - panel.frame.width / 2, y: parentFrame.midY - panel.frame.height / 2)
        )
        anchor.addChildWindow(panel, ordered: .above)
        panel.makeKeyAndOrderFront(nil)
        self.panel = panel
    }

    private func resize(panel: NSPanel, to size: CGSize) {
        let current = panel.frame
        guard size != current.size || !hasSizedPanel else { return }
        // Anchor the top edge so resize doesn't drift the panel toward
        // vertical center as content grows. Center the first visible panel
        // after the initially empty hosting view reports its real size.
        let newOrigin: NSPoint
        if !hasSizedPanel, let parent = panel.parent {
            newOrigin = NSPoint(x: parent.frame.midX - size.width / 2, y: parent.frame.midY - size.height / 2)
        } else {
            newOrigin = NSPoint(x: current.midX - size.width / 2, y: current.maxY - size.height)
        }
        hasSizedPanel = true
        panel.setFrame(NSRect(origin: newOrigin, size: size), display: true)
    }
}

/// macOS wraps AlertBody in padding so the SwiftUI shadow has room
/// inside the transparent window bounds. The outer size is reported back
/// so the NSPanel frame can follow content height.
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
