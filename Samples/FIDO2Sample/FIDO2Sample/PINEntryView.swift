// ================================================================================
// PINEntryView - PIN Entry Sheet for FIDO2 Operations
// ================================================================================
//
// iOS uses a "two-tap" flow: first tap determines PIN requirement, NFC closes,
// user enters PIN, second tap completes the operation.
// macOS keeps USB connection open throughout PIN entry.
//
// ================================================================================

import SwiftUI

// MARK: - PIN Request Handler

/// Bridges SwiftUI state with async/await PIN requests using CheckedContinuation.
@MainActor
final class PINRequestHandler: ObservableObject {
    @Published var isShowingPINEntry = false
    @Published var errorMessage: String?

    private var pendingContinuation: CheckedContinuation<String?, Never>?

    /// Requests a PIN from the user. Returns nil if cancelled.
    func requestPIN(errorMessage: String?) async -> String? {
        self.errorMessage = errorMessage
        return await withCheckedContinuation { continuation in
            pendingContinuation = continuation
            isShowingPINEntry = true
        }
    }

    func submitPIN(_ pin: String) {
        isShowingPINEntry = false
        errorMessage = nil
        pendingContinuation?.resume(returning: pin)
        pendingContinuation = nil
    }

    func cancel() {
        isShowingPINEntry = false
        errorMessage = nil
        pendingContinuation?.resume(returning: nil)
        pendingContinuation = nil
    }
}

// MARK: - PIN Entry View

struct PINEntryView: View {
    @ObservedObject var handler: PINRequestHandler
    @State private var pin = ""

    var body: some View {
        VStack(spacing: 24) {
            // Header
            VStack(spacing: 8) {
                Image(systemName: "key.fill")
                    .font(.system(size: 40))
                    .foregroundColor(.accentColor)

                Text("Enter YubiKey PIN")
                    .font(.headline)
            }

            // Error message
            if let error = handler.errorMessage {
                HStack {
                    Image(systemName: "exclamationmark.triangle.fill")
                    Text(error)
                }
                .foregroundColor(.red)
                .font(.subheadline)
            }

            // PIN input
            SecureField("PIN", text: $pin)
                .textFieldStyle(.roundedBorder)
                #if os(iOS)
                .keyboardType(.numberPad)
                #endif

            // Buttons
            HStack(spacing: 16) {
                Button("Cancel") {
                    handler.cancel()
                }
                .keyboardShortcut(.escape)

                Button("Submit") {
                    handler.submitPIN(pin)
                }
                .keyboardShortcut(.return)
                .disabled(pin.count < 4)
                .buttonStyle(.borderedProminent)
            }
        }
        .padding(24)
        .frame(minWidth: 320)
        #if os(macOS)
        .frame(width: 400)
        #endif
        .onAppear {
            pin = ""
        }
    }
}
