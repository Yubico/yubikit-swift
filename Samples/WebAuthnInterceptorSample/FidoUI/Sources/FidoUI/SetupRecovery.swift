import Foundation
import YubiKit

// pinNotSet / forcePinChange recovery flows.

extension FidoUI.Presenter {

    func recoverFromPinNotSet(
        transport: any FidoUI.TransportControllerProtocol,
        kind: CeremonyTransport,
        minPINLength: Int
    ) async throws(FidoUI.Error) {
        try await runPINSetupLoop(
            transport: transport,
            kind: kind,
            initialMinPINLength: minPINLength,
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
        kind: CeremonyTransport,
        minPINLength: Int
    ) async throws(FidoUI.Error) {
        try await runPINSetupLoop(
            transport: transport,
            kind: kind,
            initialMinPINLength: minPINLength,
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

    /// The first prompt uses GetInfo from the ceremony session. A
    /// pinPolicyViolation retry refreshes it from the setup session.
    private func runPINSetupLoop<Input: Sendable>(
        transport: any FidoUI.TransportControllerProtocol,
        kind: CeremonyTransport,
        initialMinPINLength: Int,
        nfcAlertMessage: String,
        prompt: (Int, String?) async -> Input?,
        apply: @escaping (FidoUI.ActiveSession, Input) async throws -> Void,
        onSuccess: (Input) async -> Void
    ) async throws(FidoUI.Error) {
        var currentError: String?
        var minPINLength = initialMinPINLength
        while true {
            guard let input = await prompt(minPINLength, currentError) else {
                throw .cancelled
            }
            let outcome = try await applySetup(
                transport: transport,
                kind: kind,
                nfcAlertMessage: nfcAlertMessage,
                currentMinPINLength: minPINLength
            ) { active in
                try await apply(active, input)
            }
            switch outcome {
            case .success:
                await onSuccess(input)
                return
            case .retry(let message, let updatedMinLength):
                currentError = message
                minPINLength = updatedMinLength
            case .reconnect:
                return
            case .cancelled:
                throw .cancelled
            case .fatal(let error):
                await showInlineFatal(.from(clientError: error))
                throw .webAuthn(error)
            }
        }
    }

    private func applySetup(
        transport: any FidoUI.TransportControllerProtocol,
        kind: CeremonyTransport,
        nfcAlertMessage: String,
        currentMinPINLength: Int,
        apply: (FidoUI.ActiveSession) async throws -> Void
    ) async throws(FidoUI.Error) -> SetupOutcome {
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
            case .presentationUnavailable, .operationInProgress:
                throw fidoError
            case .webAuthn(.authenticatorNotAvailable):
                // Keep the PIN form available after a failed NFC scan.
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
            return try await openNFC(transport: transport, alertMessage: nfcAlertMessage)
            #else
            throw .webAuthn(.internalError("NFC unavailable on macOS", source: .here()))
            #endif
        }
    }

    private func classifySetupError(
        _ error: any Swift.Error,
        minPINLength: Int
    ) -> SetupOutcome {
        if Task.isCancelled || error is CancellationError { return .cancelled }
        if let smartCardError = error as? SmartCardConnectionError {
            switch smartCardError {
            case .cancelled, .cancelledByUser: return .cancelled
            default: break
            }
        }
        if let fidoError = error as? FIDOConnectionError {
            if case .cancelled = fidoError { return .cancelled }
        }
        guard let sessionError = error as? CTAP2.SessionError else {
            return .fatal(
                error: .internalError("Setup failed: \(error)", source: .here())
            )
        }
        switch sessionError {
        case .connectionError(.cancelled, _), .connectionError(.cancelledByUser, _):
            return .cancelled
        case .fidoConnectionError(.cancelled, _):
            return .cancelled
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

    private enum SetupOutcome {
        case success
        case retry(message: String, minPINLength: Int)
        case reconnect
        case cancelled
        case fatal(error: WebAuthn.ClientError)
    }
}
