import SwiftUI
import YubiKit

// All `show*` panel methods. Non-awaitable shows just write `model.panel`
// and present; awaitable shows go through `awaitPanel` /
// `awaitAcknowledgement` (defined in Presenter.swift) so they can suspend
// until the user submits or cancels.

extension FidoUI.Presenter {

    // MARK: - Non-awaitable panels

    /// "Insert Your YubiKey" prompt. Non-blocking: the caller blocks on
    /// connection creation concurrently. `onCancel` must break any
    /// background wait loop; without it the sheet closes but the poll keeps
    /// running. Pass `nil` to hide the Cancel button on platforms where
    /// the bridge has no usable cancel surface (iOS USB-C / Lightning
    /// reconnect — user dismisses the sheet directly).
    func showWaitingForKey(
        operation: FidoUI.PanelModel.Operation,
        onCancel: (@Sendable () async -> Void)? = nil
    ) {
        if model.operation != operation { model.operation = operation }
        model.submittingForm = nil
        let panelCancel: (() -> Void)? = onCancel.map { hostCancel in
            { [weak self] in
                Task { await hostCancel() }
                self?.dismiss()
            }
        }
        model.panel = .waitingForKey(onCancel: panelCancel)
        present()
    }

    func showProcessing() {
        // While a form-submit is in flight, keep the form visible with
        // its in-button spinner instead of cross-fading to the standalone
        // processing panel — preserves the PIN field on rejection re-arm.
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

    /// `wasWired` controls the post-success copy: wired ceremonies append a
    /// "you can remove your YubiKey" line so the user knows the key is no
    /// longer needed; NFC ceremonies skip it (the user already lifted the
    /// key off the phone).
    func showSuccess(
        operation: FidoUI.PanelModel.Operation,
        wasWired: Bool
    ) async {
        await awaitAcknowledgement(dismissOnComplete: true) { onDismiss in
            .success(operation: operation, wasWired: wasWired, onDismiss: onDismiss)
        }
    }

    // MARK: - Pre-PIN collection (iOS NFC)

    /// Shows the PIN entry panel before opening a transport so the user
    /// can type comfortably without holding the key against the phone.
    /// The collected value lands in `lastEnteredPIN`, which `providePIN`
    /// returns to the SDK's `Authorization` closure on the next ceremony
    /// attempt.
    ///
    /// `retriesRemaining` is non-nil only on the post-rejection branch in
    /// `runCeremony`'s catch block — the panel renders with the
    /// "Incorrect PIN. N attempts remaining" inline error and clears the
    /// previous value so the user types fresh.
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

    /// Installs the touch panel for an in-stream `.waitingForUser` event.
    /// The SDK cancel closure is captured directly into the panel case;
    /// `WebAuthn.StatusStream` already dedupes consecutive duplicates so
    /// each install binds the only cancel that's still in flight.
    /// Defense in depth: bail if the panel is already showing — protects
    /// against future stream-dedup regressions.
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

    /// Installs the fingerprint panel for an in-stream
    /// `.waitingForUserVerification` event. SDK-supplied `cancel` and
    /// optional `fallbackToPIN` are captured directly into the panel
    /// case; same dedupe story as `showTouchPrompt`.
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

    /// Recovery panel for `.uvBlocked` when `clientPin` is configured. Returns
    /// normally when the user picks "Use PIN" (caller flips
    /// `ctx.uvPolicy = .skipped` for the next attempt); throws `.cancelled`
    /// on user cancel. Distinct from `showFingerprintRetry` because there's
    /// no Try Again button — the authenticator's UV won't accept a
    /// fingerprint until the key is reseated, so retrying inline is
    /// dead-ended.
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

    /// Post-miss recovery panel. Returns `true` for "Try Again" (next
    /// ceremony attempt keeps `uv: .preferred`), `false` for "Use PIN"
    /// (next attempt switches to `uv: .skipped`); throws `.cancelled` on
    /// user cancel.
    func showFingerprintRetry(
        retriesRemaining: Int
    ) async throws(FidoUI.Error) -> Bool {
        enum Choice { case useUV, usePIN, cancel }
        let choice: Choice? = await awaitPanel { resume in
            .fingerprintRetry(
                errorMessage: String(localized: "Fingerprint not recognized. Try again."),
                retries: retriesRemaining,
                onRetryUV: { resume(.useUV) },
                onUsePIN: { resume(.usePIN) },
                onCancel: { resume(.cancel) }
            )
        }

        switch choice ?? .cancel {
        case .useUV: return true
        case .usePIN: return false
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

        // Retry must not dismiss — the next ceremony attempt's
        // `.processing` panel (or PIN/UV panel surfaced via the
        // `Authorization` closure) transitions in place and avoids a
        // close/reopen flicker.
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

    /// Shows a non-retryable error in-sheet (same `ErrorPanel` UI) and awaits
    /// the user's OK dismissal. Preferred over `showFatalAlert` because it
    /// keeps the panel sheet as the single surface — a system alert stacked
    /// over the sheet reads poorly, especially on iOS.
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
