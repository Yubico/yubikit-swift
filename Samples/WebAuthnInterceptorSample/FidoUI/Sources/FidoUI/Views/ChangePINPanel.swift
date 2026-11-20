import SwiftUI

struct ChangePINPanel: View {
    let config: FidoUI.PanelModel.ChangePINConfig
    var isLoading: Bool = false
    let onSubmit: (String, String) -> Void
    let onCancel: () -> Void

    @State private var currentPin = ""
    @State private var newPin = ""
    @State private var repeatPin = ""
    @State private var isCurrentPinVisible = false
    @State private var isNewPinVisible = false
    @State private var isRepeatPinVisible = false
    @FocusState private var focusedField: Field?

    private enum Field: Hashable {
        case currentPin, newPin, repeatPin
    }

    private var currentPINIssue: PINValidationIssue? {
        currentPin.isEmpty ? nil : pinValidationIssue(currentPin, minimumCodePoints: 0)
    }

    private var validationIssue: PINValidationIssue? {
        if let currentPINIssue { return currentPINIssue }
        return pinPairValidationIssue(
            newPIN: newPin,
            repeatPIN: repeatPin,
            minimumCodePoints: config.minLength
        )
    }

    private var isValid: Bool {
        !currentPin.isEmpty
            && !newPin.isEmpty
            && !repeatPin.isEmpty
            && validationIssue == nil
    }

    private var validationMessage: String? {
        config.errorMessage ?? validationIssue?.message
    }

    var body: some View {
        VStack(spacing: 0) {
            PanelHeader(
                icon: "arrow.triangle.2.circlepath",
                title: String(localized: "Change YubiKey PIN"),
                subtitle: String(
                    localized: "For security reasons, your PIN must be changed before continuing."
                ),
                subtitleBottomPadding: 20,
                titleIdentifier: "change_pin_title",
                subtitleIdentifier: "change_pin_subtitle"
            )

            Group {
                PINFieldRow(
                    label: "Current PIN",
                    inputIdentifier: "current_pin_input",
                    text: $currentPin,
                    isVisible: $isCurrentPinVisible,
                    focus: $focusedField,
                    focusValue: .currentPin,
                    visibilityToggleIdentifier: "current_pin_visibility_toggle"
                )
                .onSubmit { focusedField = .newPin }
                .padding(.bottom, 8)

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
                    label: "Repeat New PIN",
                    inputIdentifier: "repeat_pin_input",
                    text: $repeatPin,
                    isVisible: $isRepeatPinVisible,
                    focus: $focusedField,
                    focusValue: .repeatPin,
                    visibilityToggleIdentifier: "repeat_new_pin_visibility_toggle"
                )
                .onSubmit { if isValid { onSubmit(currentPin, newPin) } }
                .padding(.bottom, 12)
            }
            .disabled(isLoading)

            ValidationText(
                message: validationMessage,
                isError: config.errorMessage != nil || (validationIssue?.isError ?? false),
                identifier: "change_pin_validation_message"
            )

            PrimaryButton(
                label: String(localized: "Change PIN"),
                identifier: "change_pin_button",
                disabled: !isValid,
                isLoading: isLoading
            ) { onSubmit(currentPin, newPin) }
            .padding(.top, 12)
            .padding(.bottom, 16)

            CancelButton(identifier: "cancel_button") { onCancel() }
        }
        .panelPadding()
        .onAppear { focusedField = .currentPin }
        .onChange(of: config.errorMessage) { oldValue, newValue in
            guard oldValue != newValue else { return }
            currentPin = ""
            newPin = ""
            repeatPin = ""
            focusedField = .currentPin
        }
    }
}

#if DEBUG
#Preview("Change PIN") {
    FidoUI.PanelView(
        model: .preview(
            .changePIN(.init(), onSubmit: { _, _ in }, onCancel: {})
        )
    )
    .fidoAlertChrome()
}
#endif
