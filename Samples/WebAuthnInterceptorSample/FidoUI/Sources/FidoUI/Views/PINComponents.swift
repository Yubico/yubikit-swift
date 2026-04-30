import SwiftUI

/// Single PIN field row: secure-text by default, toggle button reveals
/// plaintext. Used by all three PIN-entry panels.
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
            #if os(iOS)
            // .oneTimeCode keeps iOS from offering Keychain "Save Password?"
            // and from autofilling on a SecureField. PIN entry is not a
            // password — neither store nor recall it.
            .textContentType(.oneTimeCode)
            #endif

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

/// Shared validation logic for the create/change PIN forms: surfaces the
/// authenticator's error first, then min-length hint, then mismatch hint.
/// Returns nil when the field state is valid (no message to show).
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

/// Acknowledgement panel shown after a successful PIN create / change. Fires
/// `onContinue` automatically after a 2-second hold so the user doesn't have
/// to dismiss it manually; tapping Continue earlier short-circuits the wait.
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
            // `try?` swallows CancellationError — check explicitly so a torn-
            // down view doesn't still fire onContinue (mirrors SuccessPanel).
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
