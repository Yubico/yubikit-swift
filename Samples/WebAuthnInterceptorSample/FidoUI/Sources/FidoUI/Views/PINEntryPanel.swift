import SwiftUI

/// On retry (errorMessage goes non-nil) the field shakes, clears, and
/// refocuses so the user knows their PIN was rejected.
struct PINEntryPanel: View {
    let config: FidoUI.PanelModel.PINConfig
    var isLoading: Bool = false
    let onSubmit: (String) -> Void
    let onCancel: () -> Void

    @State private var pinText: String
    @State private var isPinVisible = false
    @State private var shakeCount = 0
    @FocusState private var isFieldFocused: Bool

    init(
        config: FidoUI.PanelModel.PINConfig,
        isLoading: Bool = false,
        onSubmit: @escaping (String) -> Void,
        onCancel: @escaping () -> Void
    ) {
        self.config = config
        self.isLoading = isLoading
        self.onSubmit = onSubmit
        self.onCancel = onCancel
        self._pinText = State(initialValue: config.initialPIN ?? "")
    }

    private var validationIssue: PINValidationIssue? {
        pinText.isEmpty ? nil : pinValidationIssue(pinText, minimumCodePoints: config.minLength)
    }

    private var isValid: Bool {
        !pinText.isEmpty && validationIssue == nil
    }

    var body: some View {
        VStack(spacing: 0) {
            PanelHeader(
                icon: "key.fill",
                title: String(localized: "Enter YubiKey PIN"),
                subtitle: String(localized: "Enter the PIN for your YubiKey"),
                subtitleBottomPadding: 20,
                titleIdentifier: "pin_title",
                subtitleIdentifier: "pin_subtitle"
            )

            PINFieldRow(
                label: "PIN",
                inputIdentifier: "pin_input_field",
                text: $pinText,
                isVisible: $isPinVisible,
                focus: $isFieldFocused,
                focusValue: true,
                visibilityToggleIdentifier: "pin_visibility_toggle"
            )
            .onSubmit { if isValid { onSubmit(pinText) } }
            .shake(trigger: shakeCount)
            .padding(.bottom, 12)
            .disabled(isLoading)

            if let error = config.errorMessage {
                ValidationText(message: error, isError: true, identifier: "pin_error_message")
            } else if let issue = validationIssue {
                ValidationText(
                    message: issue.message,
                    isError: issue.isError,
                    identifier: issue.isError ? "pin_too_long_message" : "pin_min_length_message"
                )
            } else if let retries = config.retries {
                ValidationText(
                    message: retriesText(retries),
                    isError: false,
                    identifier: "pin_retries_remaining"
                )
            } else {
                ValidationText(message: nil, isError: false)
            }

            PrimaryButton(
                label: String(localized: "Continue"),
                identifier: "continue_button",
                disabled: !isValid,
                isLoading: isLoading
            ) { onSubmit(pinText) }
            .padding(.top, 12)
            .padding(.bottom, 16)

            CancelButton(identifier: "cancel_button") { onCancel() }
        }
        .panelPadding()
        .onAppear { isFieldFocused = true }
        .onChange(of: config.errorMessage) { _, newValue in
            // Only shake when an error appears — not when it clears.
            guard newValue != nil else { return }
            shakeCount += 1
            pinText = ""
            isPinVisible = false
            isFieldFocused = true
        }
        .onChange(of: config.initialPIN) { oldValue, newValue in
            guard oldValue != newValue else { return }
            pinText = newValue ?? ""
        }
    }
}

#if DEBUG
#Preview("PIN Entry") {
    FidoUI.PanelView(
        model: .preview(
            .pin(.init(), onSubmit: { _ in }, onCancel: {})
        )
    )
    .fidoAlertChrome()
}

#Preview("PIN Entry - Error") {
    FidoUI.PanelView(
        model: .preview(
            .pin(
                .init(
                    errorMessage: "Incorrect PIN. 3 attempts remaining.",
                    retries: 3
                ),
                onSubmit: { _ in },
                onCancel: {}
            )
        )
    )
    .fidoAlertChrome()
}
#endif
