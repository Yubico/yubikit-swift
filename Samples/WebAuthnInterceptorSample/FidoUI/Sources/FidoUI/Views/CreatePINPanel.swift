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

    private var validationIssue: PINValidationIssue? {
        pinPairValidationIssue(
            newPIN: newPin,
            repeatPIN: repeatPin,
            minimumCodePoints: config.minLength
        )
    }

    private var isValid: Bool {
        !newPin.isEmpty && !repeatPin.isEmpty && validationIssue == nil
    }

    private var validationMessage: String? {
        config.errorMessage ?? validationIssue?.message
    }

    var body: some View {
        VStack(spacing: 0) {
            PanelHeader(
                icon: "lock.fill",
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
                    inputIdentifier: "new_pin_input",
                    text: $newPin,
                    isVisible: $isNewPinVisible,
                    focus: $focusedField,
                    focusValue: .newPin,
                    visibilityToggleIdentifier: "new_pin_visibility_toggle"
                )
                .onSubmit { focusedField = .repeatPin }
                .padding(.bottom, 8)

                PINFieldRow(
                    label: "Repeat PIN",
                    inputIdentifier: "repeat_pin_input",
                    text: $repeatPin,
                    isVisible: $isRepeatPinVisible,
                    focus: $focusedField,
                    focusValue: .repeatPin,
                    visibilityToggleIdentifier: "repeat_pin_visibility_toggle"
                )
                .onSubmit { if isValid { onSubmit(newPin) } }
                .padding(.bottom, 12)
            }
            .disabled(isLoading)

            ValidationText(
                message: validationMessage,
                isError: config.errorMessage != nil || (validationIssue?.isError ?? false),
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
        .onAppear { focusedField = .newPin }
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
