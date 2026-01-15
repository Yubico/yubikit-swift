// ================================================================================
// FIDO2Sample - A Native FIDO2/WebAuthn Demonstration
// ================================================================================
//
// This sample application demonstrates how to perform FIDO2/WebAuthn operations
//
// The focus is on CTAP2, showing the raw communication with a YubiKey
// over two transport mechanisms:
//
//   - NFC (Near Field Communication) - iOS only
//   - HID FIDO (USB Human Interface Device) - macOS only
//
// Key operations demonstrated:
//
//   1. makeCredential - Register a new credential (create a key pair)
//   2. getAssertion  - Authenticate using an existing credential
//   3. PRF Extension - Derive deterministic secrets from the authenticator
//
// ================================================================================

import SwiftUI

@main
struct FIDO2SampleApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
