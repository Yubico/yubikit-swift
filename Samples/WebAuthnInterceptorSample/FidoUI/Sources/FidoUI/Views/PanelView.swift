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

                // Min-height + natural growth: short panels render packed at
                // the top with dead space below up to the floor; tall panels
                // grow naturally beyond the floor. The macOS panel-frame
                // top-anchors on resize (see `AlertWindow.resize`), so the
                // service header stays put while the bottom edge moves.
                //
                // No transition — panels snap instantly. Any animation
                // context (even non-spring) bleeds into the layout
                // height change; `onGeometryChange` then mirrors that
                // animated height to the NSPanel per frame, so the
                // window appears to resize/bounce. Snap is also closer
                // to native macOS dialog behavior (NSAlert resizes
                // instantly).
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
                        // The Presenter already nils `onRetry` for non-retryable
                        // errors (`showError` / `showInlineFatal`); ErrorPanel
                        // gates on `if let onRetry`, no need to re-guard here.
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
                // iOS: keep a generous min height so the bottom-sheet feel
                // stays consistent across compact panels (touch prompt etc.).
                .frame(minHeight: 280, alignment: .top)
                #endif
            }
            // iOS: small phones (SE-class, 320pt) need shrink-to-fit; macOS
            // uses NSAlert-proportioned width.
            #if os(iOS)
            .frame(maxWidth: 360)
            #else
            .frame(width: 400)
            #endif
        }

        /// Shown for every panel including `.success` so it stays put
        /// during the cross-fade — gating it on panel kind would pop it
        /// out mid-transition.
        private var headerText: String {
            switch model.operation {
            case .registration:
                return String(localized: "Create passkey for \(model.serviceName)")
            case .authentication:
                return String(localized: "Sign in to \(model.serviceName)")
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
