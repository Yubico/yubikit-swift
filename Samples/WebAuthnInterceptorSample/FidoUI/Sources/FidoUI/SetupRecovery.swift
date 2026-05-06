import Foundation
import YubiKit

// pinNotSet / forcePinChange recovery flows.

extension FidoUI.Presenter {

    func recoverFromPinNotSet(
        transport: any FidoUI.TransportControllerProtocol,
        kind: CeremonyTransport
    ) async throws(FidoUI.Error) {
        try await runPINSetupLoop(
            transport: transport,
            kind: kind,
            nfcAlertMessage: FidoUI.Strings.nfcAlertSetPIN,
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

    func recoverFromForcePinChange(
        transport: any FidoUI.TransportControllerProtocol,
        kind: CeremonyTransport
    ) async throws(FidoUI.Error) {
        try await runPINSetupLoop(
            transport: transport,
            kind: kind,
            nfcAlertMessage: FidoUI.Strings.nfcAlertChangePIN,
            prompt: { [weak self] min, err in
                await self?.showChangePIN(minPINLength: min, errorMessage: err)
            },
            apply: { active, pair in try await active.changePIN(pair.current, pair.new) },
            onSuccess: { [weak self] pair in
                // Cache the NEW PIN so the post-recovery ceremony pre-fills
                // (wired) or auto-submits (NFC) without re-prompting.
                self?.updateCachedPIN(pair.new)
                await self?.showPINChanged()
            }
        )
    }

    /// minPinLength isn't known until a session opens; the first prompt
    /// uses 4, then a pinPolicyViolation retry refreshes with the
    /// authenticator's real value.
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

    /// Returns `true` to exit the recovery loop, `false` to keep
    /// looping. Throws on `.fatal` after showing the inline fatal panel.
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
                // Re-arm the PIN form rather than bailing to the outer
                // ceremony's reconnect (which would discard the typed PIN).
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
            // Stale auth token, NOT a wrong PIN. Next acquire mints a
            // fresh one — don't tell the user their PIN was wrong.
            return .retry(
                message: String(localized: "Session expired. Please try again."),
                minPINLength: minPINLength
            )
        case .ctapError(.pinBlocked, _):
            return .fatal(error: .pinBlocked(source: .here()))
        case .ctapError(.pinAuthBlocked, _):
            return .fatal(error: .pinAuthBlocked(source: .here()))
        case .connectionError, .fidoConnectionError:
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
        case cancelled
        case fatal(error: WebAuthn.ClientError)
    }
}
