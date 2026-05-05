import SwiftUI

struct PINFieldRow: View {
    let label: String
    @Binding var text: String
    @Binding var isVisible: Bool
    var visibilityToggleIdentifier: String? = nil

    var body: some View {
        HStack(spacing: 4) {
            Group {
                if isVisible {
                    TextField(label, text: $text)
                } else {
                    SecureField(label, text: $text)
                }
            }
            .textFieldStyle(.roundedBorder)

            Button {
                isVisible.toggle()
            } label: {
                Image(systemName: isVisible ? "eye" : "eye.slash")
                    .foregroundStyle(.secondary)
            }
            .buttonStyle(.plain)
            .accessibilityLabel(
                isVisible
                    ? String(localized: "Hide PIN")
                    : String(localized: "Show PIN")
            )
            .accessibilityIdentifierIfPresent(visibilityToggleIdentifier)
        }
    }
}

func minLengthMessage(_ minLength: Int) -> String {
    String(localized: "PIN must be at least \(minLength) characters")
}

/// Surfaces the authenticator's error first, then min-length hint, then
/// mismatch. Returns nil when valid.
func pinPairValidationMessage(
    errorMessage: String?,
    newPin: String,
    repeatPin: String,
    minLength: Int
) -> String? {
    if let errorMessage { return errorMessage }
    if !newPin.isEmpty && newPin.count < minLength {
        return minLengthMessage(minLength)
    }
    if !repeatPin.isEmpty && newPin != repeatPin {
        return String(localized: "PINs don't match")
    }
    return nil
}

/// Auto-continues after a 2-second hold; tap Continue to short-circuit.
struct PINConfirmationPanel: View {
    let title: String
    let message: String
    let titleIdentifier: String
    let subtitleIdentifier: String
    let continueIdentifier: String
    let onContinue: () -> Void
    @State private var didAppear = false

    var body: some View {
        VStack(spacing: 0) {
            PanelHeader(
                icon: "checkmark.circle.fill",
                tint: .green,
                title: title,
                subtitle: message,
                titleIdentifier: titleIdentifier,
                subtitleIdentifier: subtitleIdentifier
            )

            PrimaryButton(
                label: String(localized: "Continue"),
                identifier: continueIdentifier
            ) { onContinue() }
        }
        .panelPadding()
        .sensoryFeedback(.success, trigger: didAppear)
        .onAppear { didAppear = true }
        .task {
            try? await Task.sleep(for: .seconds(2))
            // `try?` swallows CancellationError — check explicitly so a
            // torn-down view doesn't still fire.
            guard !Task.isCancelled else { return }
            onContinue()
        }
    }
}

#Preview("PIN Created") {
    FidoUI.PanelView(
        model: .preview(.pinCreated(onContinue: {}))
    )
    .fidoAlertChrome()
}

#Preview("PIN Changed") {
    FidoUI.PanelView(
        model: .preview(.pinChanged(onContinue: {}))
    )
    .fidoAlertChrome()
}
