import Foundation
import SwiftUI
import YubiKit

// Ceremony orchestration: per-iteration session acquisition (wired or
// NFC), retry loop, setup-recovery dispatch.
//
// Per-ceremony transport choice is decided ONCE up-front:
//   - macOS: always wired/HID.
//   - iOS, wired key plugged in: wired path. Every body iteration
//     awaits the loop's held session. Disconnect → next iteration's
//     awaitWired suspends until the user replugs.
//   - iOS, no wired: NFC path. Prefetch PIN, then every body iteration
//     opens a fresh NFC session and closes it when done.
//
// The ceremony never switches transports mid-flight. If the user wants
// NFC after starting wired (or vice versa) they cancel and restart.

extension FidoUI.Presenter {

    /// Per-ceremony transport commitment. Decided at ceremony start
    /// based on `transport.wired() != nil`; doesn't change during the
    /// ceremony.
    enum CeremonyTransport: Sendable {
        /// macOS HID, or iOS USB-C / Lightning. Body iterations call
        /// `awaitWired`; the loop holds the connection across them.
        case wired
        /// iOS NFC. Body iterations call `openNFC` per tap; closed with
        /// success message at end of each iteration.
        case nfc
    }

    /// One ceremony attempt. Receives the iteration's session and
    /// `AttemptContext`, plus a `releaseConnection` hook that drops the
    /// underlying transport when the body knows no further authenticator
    /// I/O is needed (used by `handleAuthentication` before the picker on
    /// NFC; ignored by registration).
    typealias CeremonyBody<R> = (
        FidoUI.ActiveSession,
        FidoUI.Presenter.AttemptContext,
        @Sendable () async -> Void
    ) async throws(FidoUI.Error) -> R

    /// Main ceremony loop — drives session lifecycle + setup-recovery
    /// dispatch. Any throw out of the loop resets the presenter and
    /// tears down the transport.
    func runCeremony<R>(
        transport: any FidoUI.TransportControllerProtocol,
        operation: FidoUI.PanelModel.Operation,
        serviceName: String,
        body: @escaping CeremonyBody<R>
    ) async throws(FidoUI.Error) -> R {
        setCeremonyContext(operation: operation, serviceName: serviceName)
        // Ceremony-scoped state only — outer wrapper
        // (handleRegistration/handleAuthentication) runs `cleanup()` to
        // clear panel/canceller state. A full `reset()` here would
        // clobber the success panel between body return and showSuccess.
        defer { updateCachedPIN(nil) }

        await transport.start()

        do throws(FidoUI.Error) {
            let kind = try await pickCeremonyTransport(
                transport: transport,
                operation: operation
            )

            // NFC (iOS only): stop the wired-acquire loop and always
            // prefetch the PIN before the first tap. PIN is prioritized
            // unconditionally — typing while holding the key against
            // the phone is awkward, and the SDK silently discards a
            // prefetched value when the ceremony never enters the PIN
            // closure (UP-only / UV-only keys), so the wasted-prompt
            // path is functional, just ergonomically poor.
            if kind == .nfc {
                await transport.stopWiredLoop()
                try await collectPrefetchedPIN(retriesRemaining: nil)
            }

            // Closes the active connection mid-ceremony when no further
            // authenticator I/O is needed (e.g. before the credential picker
            // on NFC — `getAssertion` already returned fully-resolved
            // responses). Wired ceremonies pass a no-op — there's no sheet
            // to dismiss and the picker is purely local.
            let releaseConnection: @Sendable () async -> Void = { [weak self, transport, kind] in
                await self?.closeNFCIfNeeded(transport: transport, kind: kind, reason: .release)
            }

            // Per-attempt state. `pinRetries` / `uvPolicy` are mutated
            // in place by `dispatchAttemptRecovery` on retryable errors
            // so the next iteration's body sees the updated values when
            // it builds the `Authorization`.
            var ctx = FidoUI.Presenter.AttemptContext(transport: kind)
            var firstAttempt = true
            while true {
                let active = try await acquireBodySession(
                    transport: transport,
                    kind: kind,
                    operation: operation,
                    reconnecting: !firstAttempt
                )
                firstAttempt = false

                do throws(FidoUI.Error) {
                    let result = try await body(active, ctx, releaseConnection)
                    // Order matters: closeNFCIfNeeded must run before
                    // transport.cancel() so the iOS NFC sheet's success
                    // message lands. closeNFC nils nfcConnection, so
                    // cancel()'s NFC branch then no-ops; on wired the
                    // close call is a no-op and cancel() does the work.
                    //
                    // Caveat: on the multi-credential `getAssertion`
                    // path the body called `releaseConnection` to drop
                    // the NFC sheet before showing the local picker.
                    // By the time we get here `nfcConnection` is nil,
                    // so this call no-ops and the iOS system sheet
                    // never shows the "Sign-in successful" string —
                    // the alert-window success panel covers it.
                    await closeNFCIfNeeded(
                        transport: transport,
                        kind: kind,
                        reason: .success(operation: operation)
                    )
                    await showSuccess(
                        operation: operation,
                        wasWired: kind == .wired
                    )
                    await transport.cancel()
                    return result
                } catch {
                    try await dispatchAttemptRecovery(
                        error: error,
                        ctx: &ctx,
                        active: active,
                        transport: transport,
                        kind: kind,
                        operation: operation
                    )
                }
            }
        } catch {
            reset()
            await transport.cancel()
            throw error
        }
    }

    // MARK: - Per-attempt recovery dispatch

    /// Resolves a single attempt's failure: either updates `ctx` for the
    /// next iteration, drives an async setup-recovery flow, or rethrows
    /// for the outer ceremony catch to unwind. Returning normally signals
    /// the loop to continue.
    private func dispatchAttemptRecovery(
        error: FidoUI.Error,
        ctx: inout FidoUI.Presenter.AttemptContext,
        active: FidoUI.ActiveSession,
        transport: any FidoUI.TransportControllerProtocol,
        kind: CeremonyTransport,
        operation: FidoUI.PanelModel.Operation
    ) async throws(FidoUI.Error) {
        await closeNFCIfNeeded(transport: transport, kind: kind, reason: .failure)
        switch error {
        case .webAuthn(.authenticatorNotAvailable):
            // Wired: the loop has noticed and is reconnecting; next
            // awaitWired suspends until ready. NFC: next openNFC will
            // prompt for a fresh tap. Either way, just loop.
            return
        case .webAuthn(.pinRejected(let retries, _)):
            // Cached PIN was rejected (NFC: by the in-flight tap; wired:
            // by the prior connection-held attempt). Carry the retry
            // count into the next attempt so the inline form shows
            // "wrong PIN, N left"; on NFC also re-prompt out of band so
            // the cached value is fresh before the next tap.
            ctx.pinRetries = retries
            if kind == .nfc {
                try await collectPrefetchedPIN(retriesRemaining: retries)
            }
        case .webAuthn(.uvRejected(let retries, _)):
            // Built-in UV miss with retries left. Show the
            // fingerprint-retry panel; the user's choice toggles the
            // next attempt's `Authorization.uv` (Try Again → preferred,
            // Use PIN → skipped).
            let useUV = try await showFingerprintRetry(retriesRemaining: retries)
            ctx.uvPolicy = useUV ? .preferred : .skipped
        case .webAuthn(.uvBlocked):
            // Defense in depth: the SDK's `runExternalUV` already pivots to
            // PIN automatically when `clientPin` is configured, so a
            // `.uvBlocked` reaching here ought to mean "no PIN to fall back
            // to" (UV-only authenticator, or `uv: .required`). But if any
            // future SDK path leaks `.uvBlocked` while PIN is available,
            // offer the user a `Use PIN` escape hatch instead of the
            // OK-only fatal panel — symmetric with `.uvRejected`'s "Use PIN"
            // option, just without a Try Again button (the sensor won't
            // accept a fingerprint until the key is reseated).
            if active.hasPin && ctx.uvPolicy != .required {
                try await showFingerprintLocked()
                ctx.uvPolicy = .skipped
            } else {
                await showInlineFatal(.uvBlockedNoPIN)
                throw error
            }
        case .webAuthn(.pinNotSet):
            // The user owns the key and has a credential on it
            // (otherwise auth wouldn't have reached this point), so
            // allow inline PIN setup on both ceremonies rather than
            // dead-ending the user.
            try await recoverFromPinNotSet(transport: transport, kind: kind)
        case .webAuthn(.forcePinChange):
            // SDK detected forcePinChange in `acquireAuthToken` before
            // the PIN prompt — drive a changePIN flow and let the next
            // iteration retry the ceremony.
            try await recoverFromForcePinChange(
                transport: transport,
                kind: kind
            )
        default:
            throw error
        }
    }

    // MARK: - Transport choice

    /// Decide wired vs NFC for the whole ceremony. The transport's
    /// background loop is always trying to hold a wired session, so
    /// `transport.isWiredAvailable()` is the source of truth — but the
    /// loop has just been spawned and needs a moment to open the slot
    /// and finish `getInfo`. We poll for up to `wiredDecisionBudget`
    /// before committing: if the loop reports availability in that
    /// window, go wired; otherwise NFC. macOS is always wired/HID.
    ///
    /// During the wait a 200ms-debounced "Looking for security key…"
    /// panel keeps the user oriented; if the decision lands first the
    /// next panel (PIN entry / NFC prefetch) replaces it cleanly.
    private func pickCeremonyTransport(
        transport: any FidoUI.TransportControllerProtocol,
        operation: FidoUI.PanelModel.Operation
    ) async throws(FidoUI.Error) -> CeremonyTransport {
        #if os(iOS)
        let panel = Task { @MainActor [weak self] in
            try? await Task.sleep(for: Self.panelDebounceDelay)
            guard !Task.isCancelled else { return }
            self?.showWaitingForKey(operation: operation)
        }
        defer { panel.cancel() }

        // Fast path: wired loop already reports availability.
        if await transport.isWiredAvailable() { return .wired }

        // Race the budget against `awaitWired`. Whichever finishes
        // first wins; the other branch is cancelled. `awaitWired`
        // suspends in the actor on a continuation rather than polling
        // — slow keys/hubs that take >1s to enumerate are still
        // accepted on the next ceremony, when the picker fast-paths
        // off `isWiredAvailable`.
        return await withTaskGroup(of: CeremonyTransport.self) { group in
            group.addTask {
                do {
                    _ = try await transport.awaitWired()
                    return .wired
                } catch {
                    return .nfc
                }
            }
            group.addTask {
                try? await Task.sleep(for: Self.wiredDecisionBudget)
                return .nfc
            }
            let winner = await group.next() ?? .nfc
            group.cancelAll()
            return winner
        }
        #else
        return .wired
        #endif
    }

    #if os(iOS)
    /// Time the picker waits for the wired loop to populate `current`
    /// before committing to NFC. Long enough to cover
    /// `WiredSmartCardConnection.makeConnection()` + CTAP `getInfo`
    /// with headroom for slow keys / hubs; the debounced waiting
    /// panel covers the perceived stall for NFC users.
    static let wiredDecisionBudget: Duration = .milliseconds(1000)
    #endif

    /// Delay before showing a "looking for security key" panel during a
    /// wait. Stalls below this are imperceptible and shouldn't flash a
    /// panel; stalls above need a visible status so the user doesn't
    /// think the app is frozen.
    static let panelDebounceDelay: Duration = .milliseconds(200)

    // MARK: - Per-iteration acquire / close

    /// Per-iteration session acquire. Wired path awaits the loop;
    /// NFC path opens a fresh tap.
    private func acquireBodySession(
        transport: any FidoUI.TransportControllerProtocol,
        kind: CeremonyTransport,
        operation: FidoUI.PanelModel.Operation,
        reconnecting: Bool
    ) async throws(FidoUI.Error) -> FidoUI.ActiveSession {
        switch kind {
        case .wired:
            return try await waitForWiredWithPanel(
                transport: transport,
                operation: operation,
                reconnecting: reconnecting
            )
        case .nfc:
            #if os(iOS)
            let serviceName = model.serviceName
            let alertMessage =
                switch operation {
                case .registration:
                    String(localized: "Tap your YubiKey to create a passkey for \(serviceName)")
                case .authentication:
                    String(localized: "Tap your YubiKey to sign in to \(serviceName)")
                }
            return try await transport.openNFC(alertMessage: alertMessage)
            #else
            // Unreachable: macOS pickCeremonyTransport always returns .wired.
            throw .webAuthn(.internalError("NFC unavailable on macOS", source: .here()))
            #endif
        }
    }

    /// `awaitWired` wrapped in the existing 200ms-debounced waiting
    /// panel + cancel button pattern. Cancellation propagates as
    /// `.cancelled`.
    private func waitForWiredWithPanel(
        transport: any FidoUI.TransportControllerProtocol,
        operation: FidoUI.PanelModel.Operation,
        reconnecting: Bool
    ) async throws(FidoUI.Error) -> FidoUI.ActiveSession {
        // Fast path: if already held, return without showing a panel.
        if let active = await transport.wired() {
            return active
        }

        let task = Task { @Sendable in
            try await transport.awaitWired()
        }
        let panelTask = Task<Void, Never> { @MainActor [weak self] in
            try? await Task.sleep(for: Self.panelDebounceDelay)
            guard !Task.isCancelled else { return }
            self?.showWaitingPanel(
                reconnecting: reconnecting,
                operation: operation
            ) {
                task.cancel()
            }
        }
        defer { panelTask.cancel() }

        do {
            return try await withTaskCancellationHandler {
                try await task.value
            } onCancel: {
                task.cancel()
            }
        } catch let err as FidoUI.Error {
            throw err
        } catch is CancellationError {
            throw .cancelled
        } catch {
            throw .webAuthn(.internalError("Wired wait failed: \(error)", source: .here()))
        }
    }

    /// Why the NFC sheet is closing. Determines the system-sheet
    /// message: only `.success` lands a confirmation string;
    /// `.release` (mid-ceremony drop before the credential picker) and
    /// `.failure` (attempt failed, recovery taking over) close
    /// silently.
    enum NFCCloseReason: Sendable {
        case release
        case success(operation: FidoUI.PanelModel.Operation)
        case failure
    }

    /// Single NFC-close path. NFC iterations close per attempt with the
    /// optional system-sheet success message; wired keeps the
    /// connection across iterations (loop owns it) and this is a no-op.
    func closeNFCIfNeeded(
        transport: any FidoUI.TransportControllerProtocol,
        kind: CeremonyTransport,
        reason: NFCCloseReason
    ) async {
        guard kind == .nfc else { return }
        #if os(iOS)
        let message: String? =
            switch reason {
            case .release, .failure: nil
            case .success(let operation):
                operation == .registration
                    ? String(localized: "Passkey created")
                    : String(localized: "Sign-in successful")
            }
        await transport.closeNFC(successMessage: message)
        #endif
    }

    // MARK: - Waiting panel

    /// Bridge between `waitForWiredWithPanel`'s task and the unified
    /// `showWaitingForKey` panel. macOS shows a Cancel button (cancels
    /// the wait task); iOS suppresses it on reconnect (user dismisses
    /// the sheet directly) and skips the panel entirely on first wait
    /// (the picker already showed one).
    private func showWaitingPanel(
        reconnecting: Bool,
        operation: FidoUI.PanelModel.Operation,
        onCancel: @escaping @Sendable () -> Void
    ) {
        #if os(macOS)
        showWaitingForKey(
            operation: operation,
            onCancel: { onCancel() }
        )
        #else
        _ = onCancel
        if reconnecting {
            showWaitingForKey(operation: operation)
        }
        #endif
    }

}
