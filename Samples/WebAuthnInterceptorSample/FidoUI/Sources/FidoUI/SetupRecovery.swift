import Foundation
import YubiKit

// `pinNotSet` / `forcePinChange` recovery flows. The recovery loop is purely
// a composition of the presenter's existing panels (`showCreatePIN`,
// `showInlineFatal`, `showProcessing`, `updateCachedPIN`) around a
// short-lived session, so it lives as a Presenter extension rather than its
// own type.

extension FidoUI.Presenter {

    /// `pinNotSet` recovery: prompt for a new PIN, run `setPIN` against
    /// the transport, acknowledge. Ceremony retries on the next outer
    /// loop. `kind` is the ceremony's committed transport — wired
    /// reuses the loop's held session, NFC opens a fresh tap.
    func recoverFromPinNotSet(
        transport: any FidoUI.TransportControllerProtocol,
        kind: CeremonyTransport
    ) async throws(FidoUI.Error) {
        try await runPINSetupLoop(
            transport: transport,
            kind: kind,
            nfcAlertMessage: String(localized: "Tap your YubiKey to set a PIN"),
            prompt: { [weak self] min, err in
                await self?.showCreatePIN(minPINLength: min, errorMessage: err)
            },
            apply: { active, newPIN in try await active.setPIN(newPIN) },
            onSuccess: { [weak self] newPIN in
                self?.updateCachedPIN(newPIN)
                await self?.showPINCreated()
            }
        )
    }

    /// `forcePinChange` recovery: prompt for current + new PIN, run
    /// `changePIN` against the transport, acknowledge.
    func recoverFromForcePinChange(
        transport: any FidoUI.TransportControllerProtocol,
        kind: CeremonyTransport
    ) async throws(FidoUI.Error) {
        try await runPINSetupLoop(
            transport: transport,
            kind: kind,
            nfcAlertMessage: String(localized: "Tap your YubiKey to change the PIN"),
            prompt: { [weak self] min, err in
                await self?.showChangePIN(minPINLength: min, errorMessage: err)
            },
            apply: { active, pair in try await active.changePIN(pair.current, pair.new) },
            onSuccess: { [weak self] pair in
                // Replace the cached old PIN with the new one so the
                // post-recovery ceremony's PIN-entry panel pre-fills
                // (wired) or auto-submits (NFC) without re-prompting
                // the user for the value they just typed twice in
                // the change form.
                self?.updateCachedPIN(pair.new)
                await self?.showPINChanged()
            }
        )
    }

    /// Shared loop for both PIN-setup recovery flows. The
    /// authenticator's real `minPinLength` isn't known until we
    /// open a session, so the first prompt uses the default (4)
    /// and any `pinPolicyViolation` retry refreshes the form with
    /// the value surfaced from the session.
    private func runPINSetupLoop<Input: Sendable>(
        transport: any FidoUI.TransportControllerProtocol,
        kind: CeremonyTransport,
        nfcAlertMessage: String,
        prompt: (Int, String?) async -> Input?,
        apply: @escaping (FidoUI.ActiveSession, Input) async throws -> Void,
        onSuccess: (Input) async -> Void
    ) async throws(FidoUI.Error) {
        var currentError: String?
        var minPINLength = 4
        while true {
            guard let input = await prompt(minPINLength, currentError) else {
                throw .cancelled
            }
            let outcome = await applySetup(
                transport: transport,
                kind: kind,
                nfcAlertMessage: nfcAlertMessage,
                currentMinPINLength: minPINLength
            ) { active in
                try await apply(active, input)
            }
            if case .success = outcome {
                await onSuccess(input)
                return
            }
            if try await consumeSetupOutcome(
                outcome,
                currentError: &currentError,
                minPINLength: &minPINLength
            ) {
                return
            }
        }
    }

    /// Dispatches the non-success branches of a `SetupOutcome`. Returns
    /// `true` if the caller should exit the recovery loop
    /// (`.reconnect`: connection dropped, the outer ceremony will
    /// re-acquire and re-throw `.pinNotSet` / `.forcePinChange`).
    /// Returns `false` to keep looping (`.retry`, with `currentError`
    /// / `minPINLength` updated in place). Throws on `.fatal` after
    /// surfacing the inline fatal panel.
    private func consumeSetupOutcome(
        _ outcome: SetupOutcome,
        currentError: inout String?,
        minPINLength: inout Int
    ) async throws(FidoUI.Error) -> Bool {
        switch outcome {
        case .success:
            return true
        case .retry(let message, let updatedMinLength):
            currentError = message
            minPINLength = updatedMinLength
            return false
        case .reconnect:
            return true
        case .cancelled:
            throw .cancelled
        case .fatal(let error):
            await showInlineFatal(.from(clientError: error))
            throw .webAuthn(error)
        }
    }

    /// Acquires a session of the ceremony's committed kind, runs the
    /// PIN setup/change command, closes (NFC only). Swaps the
    /// createPIN/changePIN panel for `.processing` during connect +
    /// apply so the user isn't staring at a stale PIN form.
    private func applySetup(
        transport: any FidoUI.TransportControllerProtocol,
        kind: CeremonyTransport,
        nfcAlertMessage: String,
        currentMinPINLength: Int,
        apply: (FidoUI.ActiveSession) async throws -> Void
    ) async -> SetupOutcome {
        showProcessing()
        let active: FidoUI.ActiveSession
        do {
            active = try await acquireSetupSession(
                transport: transport,
                kind: kind,
                nfcAlertMessage: nfcAlertMessage
            )
        } catch let fidoError {
            switch fidoError {
            case .cancelled:
                return .cancelled
            case .webAuthn(.authenticatorNotAvailable):
                // Transient transport drop during setup — re-arm the
                // PIN form with a retry message rather than bailing
                // to the outer ceremony's reconnect (which would
                // discard the user's typed PIN).
                return .retry(
                    message: String(localized: "Failed to connect. Please try again."),
                    minPINLength: currentMinPINLength
                )
            case .webAuthn(let clientError):
                return .fatal(error: clientError)
            }
        }
        do {
            try await apply(active)
            await closeNFCIfNeeded(transport: transport, kind: kind, reason: .release)
            return .success
        } catch {
            let minPINLength = active.minPINLength
            await closeNFCIfNeeded(transport: transport, kind: kind, reason: .failure)
            return classifySetupError(error, minPINLength: minPINLength)
        }
    }

    private func acquireSetupSession(
        transport: any FidoUI.TransportControllerProtocol,
        kind: CeremonyTransport,
        nfcAlertMessage: String
    ) async throws(FidoUI.Error) -> FidoUI.ActiveSession {
        switch kind {
        case .wired:
            return try await transport.awaitWired()
        case .nfc:
            #if os(iOS)
            return try await transport.openNFC(alertMessage: nfcAlertMessage)
            #else
            throw .webAuthn(.internalError("NFC unavailable on macOS", source: .here()))
            #endif
        }
    }

    private func classifySetupError(
        _ error: any Swift.Error,
        minPINLength: Int
    ) -> SetupOutcome {
        guard let sessionError = error as? CTAP2.SessionError else {
            return .fatal(
                error: .internalError("Setup failed: \(error)", source: .here())
            )
        }
        switch sessionError {
        case .ctapError(.pinPolicyViolation, _):
            return .retry(
                message: FidoUI.ErrorInfo.from(clientError: .pinComplexity(source: .here())).message,
                minPINLength: minPINLength
            )
        case .ctapError(.pinInvalid, _):
            return .retry(
                message: String(localized: "The current PIN is incorrect."),
                minPINLength: minPINLength
            )
        case .ctapError(.pinAuthInvalid, _), .ctapError(.pinTokenExpired, _):
            // Transient protocol-level failures: PIN auth parameter
            // mismatch (token consumed by a concurrent op) or stale
            // token. Next acquire mints a fresh one. NOT a wrong-PIN
            // signal — surfacing "The current PIN is incorrect" here
            // would mislead a user who typed it correctly.
            return .retry(
                message: String(localized: "Session expired. Please try again."),
                minPINLength: minPINLength
            )
        case .ctapError(.pinBlocked, _):
            return .fatal(error: .pinBlocked(source: .here()))
        case .ctapError(.pinAuthBlocked, _):
            return .fatal(error: .pinAuthBlocked(source: .here()))
        case .connectionError, .fidoConnectionError:
            // Dead session — bail so the ceremony re-acquires.
            return .reconnect
        default:
            return .retry(
                message: String(localized: "Failed. Please try again."),
                minPINLength: minPINLength
            )
        }
    }

    fileprivate enum SetupOutcome {
        case success
        case retry(message: String, minPINLength: Int)
        case reconnect
        /// User-initiated abort during session acquire. Must
        /// terminate the recovery loop, not retry.
        case cancelled
        case fatal(error: WebAuthn.ClientError)
    }
}
