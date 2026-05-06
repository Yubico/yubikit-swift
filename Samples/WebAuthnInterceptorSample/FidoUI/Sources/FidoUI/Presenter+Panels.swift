import SwiftUI
import YubiKit

// All `show*` panel methods. Awaitable shows go through awaitPanel /
// awaitAcknowledgement so they can suspend until the user submits or cancels.

extension FidoUI.Presenter {

    // MARK: - Non-awaitable panels

    func showWaitingForKey(
        operation: FidoUI.PanelModel.Operation,
        onCancel: (@Sendable () -> Void)? = nil
    ) {
        if model.operation != operation { model.operation = operation }
        model.submittingForm = nil
        let panelCancel: (() -> Void)? = onCancel.map { hostCancel in
            { [weak self] in
                hostCancel()
                self?.dismiss()
            }
        }
        model.panel = .waitingForKey(onCancel: panelCancel)
        present()
    }

    func showProcessing() {
        // Form-submit in flight: keep the form visible with its in-button
        // spinner so the PIN field survives a rejection re-arm.
        if model.submittingForm != nil { return }
        if case .processing = model.panel, model.isPresented { return }
        model.panel = .processing
        if !model.isPresented {
            present()
        }
    }

    // MARK: - Awaitable panels (setup flow)

    func showCreatePIN(
        minPINLength: Int = 4,
        errorMessage: String? = nil
    ) async -> String? {
        await awaitPanel { resume in
            .createPIN(
                .init(minLength: minPINLength, errorMessage: errorMessage),
                onSubmit: { [weak self] pin in
                    self?.model.submittingForm = .createPIN
                    resume(pin)
                },
                onCancel: { [weak self] in
                    self?.dismiss()
                    resume(nil)
                }
            )
        }
    }

    func showChangePIN(
        minPINLength: Int = 4,
        errorMessage: String? = nil
    ) async -> (current: String, new: String)? {
        await awaitPanel { resume in
            .changePIN(
                .init(minLength: minPINLength, errorMessage: errorMessage),
                onSubmit: { [weak self] current, new in
                    self?.updateCachedPIN(current)
                    self?.model.submittingForm = .changePIN
                    resume((current, new))
                },
                onCancel: { [weak self] in
                    self?.dismiss()
                    resume(nil)
                }
            )
        }
    }

    func showPINCreated() async {
        await awaitAcknowledgement { onContinue in
            .pinCreated(onContinue: onContinue)
        }
    }

    func showPINChanged() async {
        await awaitAcknowledgement { onContinue in
            .pinChanged(onContinue: onContinue)
        }
    }

    /// Wired ceremonies append a "you can remove your YubiKey" line; NFC
    /// skips it (the user has already lifted the key).
    func showSuccess(
        operation: FidoUI.PanelModel.Operation,
        wasWired: Bool
    ) async {
        await awaitAcknowledgement(dismissOnComplete: true) { onDismiss in
            .success(operation: operation, wasWired: wasWired, onDismiss: onDismiss)
        }
    }

    // MARK: - Pre-PIN collection (iOS NFC)

    /// Prompts for the PIN before opening a transport so the user can
    /// type without holding the key against the phone. Caches into
    /// `lastEnteredPIN` for `providePIN` to consume on the next attempt.
    func collectPrefetchedPIN(
        retriesRemaining: Int?
    ) async throws(FidoUI.Error) {
        guard let pin = await showPINEntry(retriesRemaining: retriesRemaining) else {
            throw .cancelled
        }
        updateCachedPIN(pin)
    }

    // MARK: - Stream-driven panels

    func showPINEntry(
        retriesRemaining: Int?
    ) async -> String? {
        let errorMessage: String?
        let initialPIN: String?

        if let retriesRemaining {
            errorMessage = String(localized: "Incorrect PIN. \(retriesText(retriesRemaining)).")
            initialPIN = nil
        } else {
            errorMessage = nil
            initialPIN = lastEnteredPIN
        }

        let config = FidoUI.PanelModel.PINConfig(
            errorMessage: errorMessage,
            retries: retriesRemaining,
            initialPIN: initialPIN
        )
        return await awaitPanel { resume in
            .pin(
                config,
                onSubmit: { [weak self] pin in
                    self?.updateCachedPIN(pin)
                    self?.model.submittingForm = .pin
                    resume(pin)
                },
                onCancel: { [weak self] in
                    self?.dismiss()
                    resume(nil)
                }
            )
        }
    }

    func showTouchPrompt(
        cancel: @escaping @Sendable () async -> Void
    ) {
        if case .touch = model.panel, model.isPresented { return }
        model.submittingForm = nil
        model.panel = .touch(
            onCancel: { [weak self] in
                Task { await cancel() }
                self?.dismiss()
            }
        )
        present()
    }

    func showFingerprintStream(
        cancel: @escaping @Sendable () async -> Void,
        fallbackToPIN: (@Sendable () async -> Void)?
    ) {
        if case .fingerprint = model.panel, model.isPresented { return }
        model.submittingForm = nil
        model.panel = .fingerprint(
            onCancel: { [weak self] in
                Task { await cancel() }
                self?.dismiss()
            },
            onUsePIN: fallbackToPIN.map { fb in { Task { await fb() } } }
        )
        present()
    }

    /// `.uvBlocked` recovery when `clientPin` is configured. No Try Again
    /// button — the sensor won't unlock until the key is reseated.
    func showFingerprintLocked() async throws(FidoUI.Error) {
        enum Choice { case usePIN, cancel }
        let choice: Choice? = await awaitPanel { resume in
            .fingerprintLocked(
                onUsePIN: { resume(.usePIN) },
                onCancel: { resume(.cancel) }
            )
        }
        switch choice ?? .cancel {
        case .usePIN: return
        case .cancel:
            dismiss()
            throw .cancelled
        }
    }

    func showFingerprintRetry(
        retriesRemaining: Int
    ) async throws(FidoUI.Error) -> FidoUI.UVRetryChoice {
        enum Choice { case retryUV, usePIN, cancel }
        let choice: Choice? = await awaitPanel { resume in
            .fingerprintRetry(
                errorMessage: String(localized: "Fingerprint not recognized. Try again."),
                retries: retriesRemaining,
                onRetryUV: { resume(.retryUV) },
                onUsePIN: { resume(.usePIN) },
                onCancel: { resume(.cancel) }
            )
        }

        switch choice ?? .cancel {
        case .retryUV: return .retryUV
        case .usePIN: return .usePIN
        case .cancel:
            dismiss()
            throw .cancelled
        }
    }

    func showCredentialPicker(
        _ credentials: [WebAuthn.Authentication.Response]
    ) async -> Int? {
        let entries = credentials.map { credential in
            FidoUI.PanelModel.Credential(
                id: credential.credentialId,
                name: credential.user?.name ?? "Unknown",
                displayName: credential.user?.displayName
            )
        }
        return await awaitPanel { resume in
            .credentialPicker(
                entries,
                onSelect: { [weak self] index in
                    self?.dismiss()
                    resume(index)
                },
                onCancel: { [weak self] in
                    self?.dismiss()
                    resume(nil)
                }
            )
        }
    }

    func showError(_ error: WebAuthn.ClientError) async -> Bool {
        let errorInfo: FidoUI.ErrorInfo =
            switch error {
            case .noCredentials: .noCredentials(serviceName: model.serviceName)
            default: .from(clientError: error)
            }

        // Retry must not dismiss — the next attempt's panel transitions
        // in place and avoids a close/reopen flicker.
        let result: Bool? = await awaitPanel { resume in
            .error(
                errorInfo,
                onRetry: errorInfo.isRetryable ? { resume(true) } : nil,
                onDismiss: { [weak self] in
                    self?.dismiss()
                    resume(false)
                }
            )
        }
        return result ?? false
    }

    /// Non-retryable error rendered in-sheet — preferred over a system
    /// alert stacked over the sheet (reads poorly on iOS).
    func showInlineFatal(_ info: FidoUI.ErrorInfo) async {
        _ = await awaitPanel { (resume: @escaping (Void?) -> Void) in
            .error(
                info,
                onRetry: nil,
                onDismiss: { [weak self] in
                    self?.dismiss()
                    resume(())
                }
            )
        }
    }
}
