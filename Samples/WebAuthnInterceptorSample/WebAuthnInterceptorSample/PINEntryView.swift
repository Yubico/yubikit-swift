//
//  PINEntryView.swift
//  WebAuthnInterceptorSample
//

import SwiftUI

struct PINEntryView: View {
    let onSubmit: (String) -> Void
    let onCancel: () -> Void
    var errorMessage: String?

    @State private var pin = ""
    @FocusState private var isFocused: Bool

    private var isValid: Bool { pin.count >= 4 }

    var body: some View {
        VStack(spacing: 16) {
            Text("Enter YubiKey PIN")
                .font(.headline)

            if let errorMessage {
                Text(errorMessage)
                    .font(.caption)
                    .foregroundStyle(.red)
            }

            SecureField("PIN", text: $pin)
                .textFieldStyle(.roundedBorder)
                .focused($isFocused)
                .onSubmit { if isValid { onSubmit(pin) } }

            if !pin.isEmpty && !isValid {
                Text("PIN must be at least 4 characters")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            HStack(spacing: 12) {
                Button("Cancel", action: onCancel)
                    .buttonStyle(.bordered)
                Button("Done") { onSubmit(pin) }
                    .buttonStyle(.borderedProminent)
                    .disabled(!isValid)
            }
        }
        .padding()
        .onAppear { isFocused = true }
    }
}

// MARK: - PIN Request Handler

@MainActor
class PINRequestHandler: ObservableObject {
    @Published var isShowingPINEntry = false
    @Published var errorMessage: String?
    private var pendingContinuation: CheckedContinuation<String?, Never>?

    func requestPIN(errorMessage: String? = nil) async -> String? {
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

#Preview {
    PINEntryView(onSubmit: { _ in }, onCancel: {})
}
