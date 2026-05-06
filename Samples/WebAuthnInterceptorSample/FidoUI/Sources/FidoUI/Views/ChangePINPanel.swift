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

    private var isValid: Bool {
        !currentPin.isEmpty
            && newPin.count >= config.minLength
            && !repeatPin.isEmpty
            && newPin == repeatPin
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
                icon: "key.rotate",
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
                    text: $currentPin,
                    isVisible: $isCurrentPinVisible,
                    visibilityToggleIdentifier: "current_pin_visibility_toggle"
                )
                .focused($focusedField, equals: .currentPin)
                .accessibilityIdentifier("current_pin_input")
                .onSubmit { focusedField = .newPin }
                .padding(.bottom, 8)

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
                    label: "Repeat New PIN",
                    text: $repeatPin,
                    isVisible: $isRepeatPinVisible,
                    visibilityToggleIdentifier: "repeat_new_pin_visibility_toggle"
                )
                .focused($focusedField, equals: .repeatPin)
                .accessibilityIdentifier("repeat_pin_input")
                .onSubmit { if isValid { onSubmit(currentPin, newPin) } }
                .padding(.bottom, 12)
            }
            .disabled(isLoading)

            ValidationText(
                message: validationMessage,
                isError: config.errorMessage != nil,
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
        .defaultFocus($focusedField, .currentPin)
        .onChange(of: config.errorMessage) { oldValue, newValue in
            guard oldValue != newValue else { return }
            currentPin = ""
            newPin = ""
            repeatPin = ""
            focusedField = .currentPin
        }
    }
}

#Preview("Change PIN") {
    FidoUI.PanelView(
        model: .preview(
            .changePIN(.init(), onSubmit: { _, _ in }, onCancel: {})
        )
    )
    .fidoAlertChrome()
}
