import SwiftUI
import YubiKit

// Stream-driven orchestration: entry points, retry-on-error loop, and
// the status-stream drain.

extension FidoUI.Presenter {

    /// Built fresh per body iteration so each call binds a new
    /// `Authorization` (UV policy may have flipped to .skipped after a
    /// "Use PIN" choice).
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
            // Extensions (PRF, largeBlob) already ran inside getAssertion,
            // so picking is local. Drop the NFC sheet first.
            await releaseConnection()
            guard let index = await self.showCredentialPicker(matches) else {
                throw .cancelled
            }
            return matches[index]
        }
    }

    /// SDK `Authorization.providePIN` target. NFC consumes the cached
    /// prefetched value; wired shows the inline PIN form.
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

    func retryOnError<R>(
        body: () async throws(FidoUI.Error) -> R
    ) async throws(FidoUI.Error) -> R {
        while true {
            do throws(FidoUI.Error) {
                return try await body()
            } catch .webAuthn(let clientError) {
                try await handleClientError(clientError)
            }
        }
    }

    private func handleClientError(
        _ error: WebAuthn.ClientError
    ) async throws(FidoUI.Error) {
        switch error {
        case .authenticatorNotAvailable, .pinNotSet, .forcePinChange,
            .pinRejected, .uvRejected, .uvBlocked:
            // Recovery and per-attempt reject signals propagate to
            // runCeremony which dispatches the right flow. Showing a
            // Retry/Cancel panel here would hide the recovery path.
            throw .webAuthn(error)

        case .pinBlocked, .pinAuthBlocked:
            _ = await showError(error)
            throw .webAuthn(error)

        default:
            let shouldRetry = await showError(error)
            if !shouldRetry { throw .webAuthn(error) }
        }
    }

    /// Drains the status stream into panels. PIN entry is out-of-band via
    /// the SDK's `Authorization.providePIN` closure, not the stream.
    /// A stream that ends without `.finished` surfaces as `.internalError`
    /// rather than crashing.
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
