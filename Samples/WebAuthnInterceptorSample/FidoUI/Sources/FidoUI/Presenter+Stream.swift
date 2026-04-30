import SwiftUI
import YubiKit

// Stream-driven orchestration: ceremony entry points, the per-ceremony
// `Authorization` builder the SDK invokes for PIN entry, the retry-on-error
// loop, and the status-stream drain.

extension FidoUI.Presenter {

    /// Stream factory used by `handleRegistration` / `handleAuthentication`.
    /// Built by ``FidoUI`` per body iteration so each call binds a fresh
    /// `Authorization` whose UV policy reflects any mid-ceremony "Use PIN"
    /// switch and whose `providePIN` closure routes back through the
    /// presenter's panel layer.
    typealias CeremonyStream<R: Sendable> =
        @Sendable () async -> WebAuthn.StatusStream<R>

    func handleRegistration(
        makeCredential: @escaping CeremonyStream<WebAuthn.Registration.Response>,
        rpId: String
    ) async throws(FidoUI.Error) -> WebAuthn.Registration.Response {
        fidoLog("Presenter", "handleRegistration(rpId: \(rpId), serviceName: \(self.model.serviceName))")
        defer { cleanup() }

        return try await retryOnError { () throws(FidoUI.Error) in
            try await self.iterate(await makeCredential())
        }
    }

    func handleAuthentication(
        getAssertion: @escaping CeremonyStream<[WebAuthn.Authentication.Response]>,
        rpId: String,
        releaseConnection: @Sendable () async -> Void
    ) async throws(FidoUI.Error) -> WebAuthn.Authentication.Response {
        fidoLog("Presenter", "handleAuthentication(rpId: \(rpId), serviceName: \(self.model.serviceName))")
        defer { cleanup() }

        return try await retryOnError { () throws(FidoUI.Error) in
            let matches = try await self.iterate(await getAssertion())
            if matches.count == 1 {
                return matches[0]
            }
            fidoLog("Presenter", "  Multiple credentials (\(matches.count)), showing picker")
            // Extensions (PRF, largeBlob) already ran during the SDK
            // assertion call, so picking is local. Drop the NFC sheet
            // before the picker — keeping it open while the user reads
            // the list is misleading and forces a manual dismiss.
            await releaseConnection()
            guard let index = await self.showCredentialPicker(matches) else {
                throw .cancelled
            }
            return matches[index]
        }
    }

    /// SDK `Authorization.providePIN` target. NFC ceremonies consume the
    /// prefetched cached value (collected before the first tap, refreshed
    /// by the outer ceremony catch on `.pinRejected`); wired ceremonies
    /// show the inline PIN form with `retries` rendered as the inline
    /// "wrong PIN, N attempts remaining" message when non-nil.
    func askForPIN(
        retries: Int?,
        transport: CeremonyTransport
    ) async -> WebAuthn.Authorization.PINReply {
        fidoLog("Presenter", "askForPIN(transport: \(transport), retries: \(retries.map(String.init) ?? "nil"))")
        if transport == .nfc, let cached = lastEnteredPIN {
            return .pin(cached)
        }
        guard let pin = await showPINEntry(retriesRemaining: retries) else {
            return .cancel
        }
        return .pin(pin)
    }

    /// Retries `body` when the user taps Retry on the error panel.
    /// Non-retryable or cancelled errors propagate to the caller.
    func retryOnError<R>(
        body: () async throws(FidoUI.Error) -> R
    ) async throws(FidoUI.Error) -> R {
        while true {
            do throws(FidoUI.Error) {
                return try await body()
            } catch .webAuthn(let clientError) {
                try await handleClientError(clientError)
            }
            // `.cancelled` and `.forcePinChangeRequired` propagate unchanged.
        }
    }

    private func handleClientError(
        _ error: WebAuthn.ClientError
    ) async throws(FidoUI.Error) {
        switch error {
        case .authenticatorNotAvailable, .pinNotSet, .forcePinChange,
            .pinRejected, .uvRejected, .uvBlocked:
            // Reconnect-required errors, setup-recovery errors (no PIN
            // configured), and the per-attempt PIN/UV reject signals all
            // propagate to the host (`runCeremony`) which dispatches the
            // right recovery flow. Showing the generic error panel here
            // would dead-end the user on a Retry/Cancel choice that either
            // loops the same (cached) value or hides the recovery path.
            throw .webAuthn(error)

        case .pinBlocked, .pinAuthBlocked:
            // `ErrorInfo.from(_:)` already marks these as `severity: .critical`
            // and `isRetryable: false` — the error panel shows OK only. Keeps
            // the user in-sheet instead of stacking a system alert over it,
            // which matches the yubikit-android pattern of inline error text.
            _ = await showError(error)
            throw .webAuthn(error)

        // `.cancelled` is intentionally not handled here — `iterate`
        // translates a stream-level cancel directly to `FidoUI.Error.cancelled`
        // before `retryOnError` can catch it, so this switch can never see it.

        default:
            let shouldRetry = await showError(error)
            if !shouldRetry { throw .webAuthn(error) }
        }
    }

    /// Drains a WebAuthn status stream, dispatching `.processing`,
    /// `.waitingForUser`, and `.waitingForUserVerification` to panels.
    /// PIN entry is delivered out-of-band through the SDK's
    /// `Authorization.providePIN` closure, not the stream.
    ///
    /// `.cancelled` from inside the stream surfaces as
    /// `FidoUI.Error.cancelled` (not `.webAuthn(.cancelled)`) for parity
    /// with other cancel paths — the rest of the presenter never has to
    /// special-case the wrapped form.
    ///
    /// A stream that ends without yielding `.finished` is an SDK contract
    /// violation. We surface it as `.internalError` rather than crashing
    /// the host — `WebAuthn.StatusStream.value()` `preconditionFailure`s
    /// on the same condition, but in a sample app a thrown error gives the
    /// user a "please report this" panel instead of taking the process down.
    func iterate<R: Sendable>(
        _ stream: WebAuthn.StatusStream<R>
    ) async throws(FidoUI.Error) -> R {
        do throws(WebAuthn.ClientError) {
            for try await status in stream {
                switch status {
                case .processing:
                    fidoLog("Presenter", "  .processing")
                    showProcessing()
                case .waitingForUser(let cancel):
                    fidoLog("Presenter", "  .waitingForUser")
                    showTouchPrompt(cancel: cancel)
                case .waitingForUserVerification(let cancel, let fallbackToPIN):
                    fidoLog("Presenter", "  .waitingForUserVerification")
                    showFingerprintStream(
                        cancel: cancel,
                        fallbackToPIN: fallbackToPIN
                    )
                case .finished(let result):
                    fidoLog("Presenter", "  .finished")
                    return result
                }
            }
            throw .internalError(
                "WebAuthn.StatusStream ended without yielding .finished",
                source: .here()
            )
        } catch .cancelled {
            throw .cancelled
        } catch {
            throw .webAuthn(error)
        }
    }
}
