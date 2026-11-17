import SwiftUI

#if os(iOS)
struct TestWindowReader: UIViewRepresentable {
    func makeUIView(context: Context) -> UIView { WindowView(frame: .zero) }
    func updateUIView(_ view: UIView, context: Context) {}

    private final class WindowView: UIView {
        override func didMoveToWindow() {
            super.didMoveToWindow()
            Runner.window = window
        }
    }
}
#elseif os(macOS)
struct TestWindowReader: NSViewRepresentable {
    func makeNSView(context: Context) -> NSView { WindowView(frame: .zero) }
    func updateNSView(_ view: NSView, context: Context) {}

    private final class WindowView: NSView {
        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            Runner.window = window
        }
    }
}
#endif
