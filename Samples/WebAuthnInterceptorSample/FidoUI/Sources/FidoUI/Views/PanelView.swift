import SwiftUI

extension FidoUI {
    struct PanelView: View {
        let model: FidoUI.PanelModel

        init(model: FidoUI.PanelModel) {
            self.model = model
        }

        var body: some View {
            VStack(spacing: 0) {
                Divider()

                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Image(systemName: headerIcon)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .accessibilityHidden(true)

                    Text(headerText)
                        .font(.subheadline.weight(.medium))
                        .foregroundStyle(.primary)
                        .multilineTextAlignment(.leading)
                        .lineLimit(2)
                        .truncationMode(.middle)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 24)
                .padding(.vertical, 14)
                .accessibilityElement(children: .combine)
                .accessibilityAddTraits(.isHeader)
                .accessibilityIdentifier("panel_service_header")

                Divider()

                // No transition — any animation bleeds into the layout
                // height change, and `onGeometryChange` then mirrors that
                // animated height to the NSPanel per frame, making the
                // window appear to bounce.
                Group {
                    switch model.panel {
                    case .waitingForKey(let onCancel):
                        WaitingForKeyPanel(onCancel: onCancel)
                    case .processing:
                        ProcessingPanel()
                    case .touch(let onCancel):
                        TouchPromptPanel(onCancel: onCancel)
                    case .pin(let config, let onSubmit, let onCancel):
                        PINEntryPanel(
                            config: config,
                            isLoading: model.submittingForm == .pin,
                            onSubmit: onSubmit,
                            onCancel: onCancel
                        )
                    case .fingerprint(let onCancel, let onUsePIN):
                        FingerprintPanel(onCancel: onCancel, onUsePIN: onUsePIN)
                    case .fingerprintRetry(let errorMessage, let retries, let onRetryUV, let onUsePIN, let onCancel):
                        FingerprintRetryPanel(
                            errorMessage: errorMessage,
                            retries: retries,
                            onRetryUV: onRetryUV,
                            onUsePIN: onUsePIN,
                            onCancel: onCancel
                        )
                    case .fingerprintLocked(let onUsePIN, let onCancel):
                        FingerprintLockedPanel(
                            onUsePIN: onUsePIN,
                            onCancel: onCancel
                        )
                    case .credentialPicker(let credentials, let onSelect, let onCancel):
                        CredentialPickerPanel(
                            credentials: credentials,
                            serviceName: model.serviceName,
                            onSelect: onSelect,
                            onCancel: onCancel
                        )
                    case .createPIN(let config, let onSubmit, let onCancel):
                        CreatePINPanel(
                            config: config,
                            isLoading: model.submittingForm == .createPIN,
                            onSubmit: onSubmit,
                            onCancel: onCancel
                        )
                    case .changePIN(let config, let onSubmit, let onCancel):
                        ChangePINPanel(
                            config: config,
                            isLoading: model.submittingForm == .changePIN,
                            onSubmit: onSubmit,
                            onCancel: onCancel
                        )
                    case .pinCreated(let onContinue):
                        PINConfirmationPanel(
                            title: String(localized: "PIN Created"),
                            message: String(
                                localized: "Your YubiKey PIN has been set."
                            ),
                            titleIdentifier: "pin_created_title",
                            subtitleIdentifier: "pin_created_subtitle",
                            continueIdentifier: "pin_created_continue_button",
                            onContinue: onContinue
                        )
                    case .pinChanged(let onContinue):
                        PINConfirmationPanel(
                            title: String(localized: "PIN Changed"),
                            message: String(
                                localized:
                                    "Your YubiKey PIN has been changed."
                            ),
                            titleIdentifier: "pin_changed_title",
                            subtitleIdentifier: "pin_changed_subtitle",
                            continueIdentifier: "pin_changed_continue_button",
                            onContinue: onContinue
                        )
                    case .error(let info, let onRetry, let onDismiss):
                        ErrorPanel(
                            info: info,
                            onRetry: onRetry,
                            onDismiss: onDismiss
                        )
                    case .success(let operation, let wasWired, let onDismiss):
                        SuccessPanel(
                            operation: operation,
                            wasWired: wasWired,
                            onDismiss: onDismiss
                        )
                    }
                }
                .id(model.panel.kind)
                #if os(iOS)
                // Min height keeps the bottom-sheet feel consistent across
                // compact panels (touch prompt etc.).
                .frame(minHeight: 280, alignment: .top)
                #endif
            }
            #if os(iOS)
            .frame(maxWidth: 360)
            #else
            .frame(width: 400)
            #endif
        }

        private var headerText: String {
            let name = model.serviceName
            switch model.operation {
            case .registration:
                return name.isEmpty
                    ? String(localized: "Create a passkey")
                    : String(localized: "Create passkey for \(name)")
            case .authentication:
                return name.isEmpty
                    ? String(localized: "Sign in")
                    : String(localized: "Sign in to \(name)")
            }
        }

        private var headerIcon: String {
            switch model.operation {
            case .registration: "lock.fill"
            case .authentication: "lock.open.fill"
            }
        }
    }
}

#Preview("Header - Registration") {
    FidoUI.PanelView(
        model: .preview(
            .waitingForKey(onCancel: {}),
            operation: .registration,
            serviceName: "example.com"
        )
    )
    .fidoAlertChrome()
}

#Preview("Header - Authentication") {
    FidoUI.PanelView(
        model: .preview(
            .waitingForKey(onCancel: {}),
            operation: .authentication,
            serviceName: "example.com"
        )
    )
    .fidoAlertChrome()
}

#Preview("Header - Long Service Name") {
    FidoUI.PanelView(
        model: .preview(
            .waitingForKey(onCancel: {}),
            operation: .authentication,
            serviceName: "login.accounts.very-long-service-name.example.com"
        )
    )
    .fidoAlertChrome()
}

#Preview("Success Hides Header") {
    FidoUI.PanelView(
        model: .preview(
            .success(operation: .registration, wasWired: true, onDismiss: {}),
            operation: .registration,
            serviceName: "example.com"
        )
    )
    .fidoAlertChrome()
}
