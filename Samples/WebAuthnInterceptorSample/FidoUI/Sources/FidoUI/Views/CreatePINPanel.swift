import SwiftUI

struct CreatePINPanel: View {
    let config: FidoUI.PanelModel.CreatePINConfig
    var isLoading: Bool = false
    let onSubmit: (String) -> Void
    let onCancel: () -> Void

    @State private var newPin = ""
    @State private var repeatPin = ""
    @State private var isNewPinVisible = false
    @State private var isRepeatPinVisible = false
    @FocusState private var focusedField: Field?

    private enum Field: Hashable { case newPin, repeatPin }

    private var isValid: Bool {
        newPin.count >= config.minLength && !repeatPin.isEmpty && newPin == repeatPin
    }

    private var validationMessage: String? {
        pinPairValidationMessage(
            errorMessage: config.errorMessage,
            newPin: newPin,
            repeatPin: repeatPin,
            minLength: config.minLength
        )
    }

    var body: some View {
        VStack(spacing: 0) {
            PanelHeader(
                icon: "lock.badge.plus",
                title: String(localized: "Set Up YubiKey PIN"),
                subtitle: String(
                    localized: "Your YubiKey requires a PIN to continue. Create one now."
                ),
                subtitleBottomPadding: 20,
                titleIdentifier: "create_pin_title",
                subtitleIdentifier: "create_pin_subtitle"
            )

            Group {
                PINFieldRow(
                    label: "New PIN",
                    text: $newPin,
                    isVisible: $isNewPinVisible,
                    visibilityToggleIdentifier: "new_pin_visibility_toggle"
                )
                .focused($focusedField, equals: .newPin)
                .accessibilityIdentifier("new_pin_input")
                .onSubmit { focusedField = .repeatPin }
                .padding(.bottom, 8)

                PINFieldRow(
                    label: "Repeat PIN",
                    text: $repeatPin,
                    isVisible: $isRepeatPinVisible,
                    visibilityToggleIdentifier: "repeat_pin_visibility_toggle"
                )
                .focused($focusedField, equals: .repeatPin)
                .accessibilityIdentifier("repeat_pin_input")
                .onSubmit { if isValid { onSubmit(newPin) } }
                .padding(.bottom, 12)
            }
            .disabled(isLoading)

            ValidationText(
                message: validationMessage,
                isError: config.errorMessage != nil,
                identifier: "create_pin_validation_message"
            )

            PrimaryButton(
                label: String(localized: "Create PIN"),
                identifier: "create_pin_button",
                disabled: !isValid,
                isLoading: isLoading
            ) { onSubmit(newPin) }
            .padding(.top, 12)
            .padding(.bottom, 16)

            CancelButton(identifier: "cancel_button") { onCancel() }
        }
        .panelPadding()
        .defaultFocus($focusedField, .newPin)
        .onChange(of: config.errorMessage) { oldValue, newValue in
            guard oldValue != newValue else { return }
            newPin = ""
            repeatPin = ""
            focusedField = .newPin
        }
    }
}

#Preview("Create PIN") {
    FidoUI.PanelView(
        model: .preview(
            .createPIN(.init(), onSubmit: { _ in }, onCancel: {})
        )
    )
    .fidoAlertChrome()
}

#Preview("Create PIN - Error") {
    FidoUI.PanelView(
        model: .preview(
            .createPIN(
                .init(errorMessage: "PIN doesn't meet complexity requirements."),
                onSubmit: { _ in },
                onCancel: {}
            )
        )
    )
    .fidoAlertChrome()
}
