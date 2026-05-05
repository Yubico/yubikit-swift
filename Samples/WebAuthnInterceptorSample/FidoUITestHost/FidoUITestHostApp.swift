import SwiftUI

@main
struct FidoUITestHostApp: App {
    var body: some Scene {
        #if os(macOS)
        // `WindowGroup` sometimes doesn't open a window under XCUITest launch.
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
