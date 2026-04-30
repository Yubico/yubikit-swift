import Foundation
import YubiKit

extension FidoUI {

    /// One open session, ready for the ceremony body. `client` is what
    /// runs `makeCredential` / `getAssertion`; `setPIN` / `changePIN`
    /// route through whatever the controller's underlying transport is
    /// (production: real CTAP2.Session methods; tests: mock callbacks).
    /// Closing is owned by the controller.
    struct ActiveSession: Sendable {
        let client: WebAuthn.Client
        let minPINLength: Int
        /// Mirror of `info.options.clientPin == true`. Read by
        /// `dispatchAttemptRecovery` to decide whether a `.uvBlocked`
        /// recovery panel should offer "Use PIN" (PIN configured) or
        /// dead-end at "remove and reinsert" (UV-only authenticator).
        let hasPin: Bool
        let setPIN: @Sendable (_ pin: String) async throws -> Void
        let changePIN: @Sendable (_ current: String, _ new: String) async throws -> Void
    }

    /// Transport contract used by the Presenter. The model is:
    ///
    /// 1. `start()` spawns a background loop that *continuously* tries to
    ///    hold a wired session (USB-C/Lightning on iOS, HID FIDO on
    ///    macOS). On any disconnect the loop iterates and tries again.
    /// 2. `wired()` is a sync probe — returns the current wired session
    ///    if held, nil otherwise. Used to decide at ceremony start
    ///    whether NFC prefetch is needed (iOS).
    /// 3. `awaitWired()` blocks until `current` is non-nil. Used by the
    ///    body each iteration on the wired/HID path; if the user
    ///    unplugs mid-ceremony, the next iteration's `awaitWired` just
    ///    suspends until they replug.
    /// 4. `openNFC(...)` is a one-shot bypass of the loop, used on iOS
    ///    when no wired is available. Each tap opens a fresh
    ///    NFCSmartCardConnection; `closeNFC` writes the system-sheet
    ///    success message and closes.
    /// 5. `cancel()` stops the loop and closes any held connection.
    protocol TransportControllerProtocol: Sendable {

        /// Spawn the wired-acquire loop. Idempotent.
        func start() async

        /// Sync probe: the currently-held wired session, or nil. Reading
        /// returns `Optional<ActiveSession>` because the body wants the
        /// session shape regardless of whether wired or NFC is the
        /// underlying transport — the Presenter rebuilds it every read.
        func wired() async -> ActiveSession?

        /// True when the wired-acquire loop is expected to deliver a
        /// session imminently. Used by `pickCeremonyTransport` to decide
        /// wired vs NFC without forcing a session build at peek time —
        /// production: `current != nil`; mocks: configured per scenario.
        func isWiredAvailable() async -> Bool

        /// Block until the wired-acquire loop has a connection ready.
        /// Cancellation propagates as `.cancelled`.
        func awaitWired() async throws(FidoUI.Error) -> ActiveSession

        /// Stop the background wired-acquire loop. Used by the ceremony
        /// once it has committed to NFC so the loop doesn't keep polling
        /// USB-C / Lightning enumeration for the rest of the ceremony.
        /// Idempotent.
        func stopWiredLoop() async

        #if os(iOS)
        /// One-shot NFC open. Builds CTAP session + WebAuthn.Client over
        /// a fresh `NFCSmartCardConnection(alertMessage:)`. The caller
        /// must `closeNFC` after the body iteration completes.
        func openNFC(alertMessage: String) async throws(FidoUI.Error) -> ActiveSession

        /// Close the in-flight NFC session. On success
        /// (`successMessage != nil`), the message is written to the iOS
        /// system sheet ("Sign-in successful" / "Passkey created") before
        /// it dismisses.
        func closeNFC(successMessage: String?) async
        #endif

        /// Stop the loop and close any held connection. Safe to call
        /// multiple times.
        func cancel() async
    }
}
