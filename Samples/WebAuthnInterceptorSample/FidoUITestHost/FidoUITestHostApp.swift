import SwiftUI

@main
struct FidoUITestHostApp: App {
    var body: some Scene {
        #if os(macOS)
        // On macOS, `WindowGroup` doesn't reliably create a window when the
        // app is launched non-interactively (XCUITest via posix_spawn,
        // launchd, etc.) — process appears in Dock but no window opens.
        // `Window` presents one window unconditionally; iOS doesn't have
        // this issue and `Window` isn't available there pre-iOS-26.
        Window("FIDO UI Test Host", id: "main") {
            E2EScenariosView()
        }
        #else
        WindowGroup {
            E2EScenariosView()
        }
        #endif
    }
}
