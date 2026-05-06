import Foundation
import YubiKit

extension FidoUI {

    /// One open session, ready for the ceremony body.
    struct ActiveSession: Sendable {
        let client: WebAuthn.Client
        let minPINLength: Int
        /// Mirror of `info.options.clientPin == true`. Read by
        /// `dispatchAttemptRecovery` to decide whether a `.uvBlocked`
        /// recovery offers "Use PIN" or dead-ends at "remove and reinsert".
        let hasPin: Bool
        let setPIN: @Sendable (_ pin: String) async throws -> Void
        let changePIN: @Sendable (_ current: String, _ new: String) async throws -> Void
    }

    /// Transport contract used by the Presenter. The controller runs a
    /// background loop that continuously tries to hold a wired session
    /// (HID on macOS, USB-C/Lightning on iOS). NFC is opened one-shot per
    /// tap on iOS.
    protocol TransportControllerProtocol: Sendable {

        func start() async

        func wired() async -> ActiveSession?

        /// True when the wired-acquire loop should deliver a session
        /// imminently. Used by `pickCeremonyTransport` to choose wired vs
        /// NFC without forcing a session build at peek time.
        func isWiredAvailable() async -> Bool

        /// Block until a wired session is ready.
        func awaitWired() async throws(FidoUI.Error) -> ActiveSession

        /// Stop polling for wired — used after the ceremony commits to NFC.
        func stopWiredLoop() async

        #if os(iOS)
        /// One-shot NFC open. Caller must `closeNFC` after the body
        /// iteration completes.
        func openNFC(alertMessage: String) async throws(FidoUI.Error) -> ActiveSession

        /// On success (`successMessage != nil`), the message lands on
        /// the iOS system sheet before it dismisses.
        func closeNFC(successMessage: String?) async
        #endif

        func cancel() async
    }
}
