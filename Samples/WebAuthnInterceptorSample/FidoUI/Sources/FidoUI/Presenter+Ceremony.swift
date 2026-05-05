import Foundation
import SwiftUI
import YubiKit

// Ceremony orchestration: per-iteration session acquire, retry loop,
// setup-recovery dispatch.
//
// Transport choice is decided once up-front and never switches. macOS is
// always wired/HID. iOS picks wired if a key is plugged in, otherwise NFC.
// Wired iterations await the loop's held session; NFC iterations open and
// close a fresh tap per attempt.

extension FidoUI.Presenter {

    enum CeremonyTransport: Sendable {
        case wired
        case nfc
    }

    /// `releaseConnection` drops the underlying transport when the body
    /// knows no further authenticator I/O is needed (used by
    /// `handleAuthentication` before the picker on NFC).
    typealias CeremonyBody<R> = (
        FidoUI.ActiveSession,
        FidoUI.Presenter.AttemptContext,
        @Sendable () async -> Void
    ) async throws(FidoUI.Error) -> R

    func runCeremony<R>(
        transport: any FidoUI.TransportControllerProtocol,
        operation: FidoUI.PanelModel.Operation,
        serviceName: String,
        body: @escaping CeremonyBody<R>
    ) async throws(FidoUI.Error) -> R {
        setCeremonyContext(operation: operation, serviceName: serviceName)
        // Outer wrapper runs cleanup(); a reset() here would clobber the
        // success panel between body return and showSuccess.
        defer { updateCachedPIN(nil) }

        await transport.start()

        do throws(FidoUI.Error) {
            let kind = try await pickCeremonyTransport(
                transport: transport,
                operation: operation
            )

            // NFC: PIN is prefetched unconditionally — typing against the
            // phone is awkward. Discarded silently if the ceremony never
            // calls the PIN closure (UP-only / UV-only keys).
            if kind == .nfc {
                await transport.stopWiredLoop()
                try await collectPrefetchedPIN(retriesRemaining: nil)
            }

            let releaseConnection: @Sendable () async -> Void = { [weak self, transport, kind] in
                await self?.closeNFCIfNeeded(transport: transport, kind: kind, reason: .release)
            }

            var ctx = FidoUI.Presenter.AttemptContext(transport: kind)
            while true {
                let active = try await acquireBodySession(
                    transport: transport,
                    kind: kind,
                    operation: operation
                )

                do throws(FidoUI.Error) {
                    let result = try await body(active, ctx, releaseConnection)
                    // Close NFC before transport.cancel() so the iOS sheet's
                    // success message lands.
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
            return
        case .webAuthn(.pinRejected(let retries, _)):
            ctx.pinRetries = retries
            if kind == .nfc {
                // Refresh the cached PIN before the next tap.
                try await collectPrefetchedPIN(retriesRemaining: retries)
            }
        case .webAuthn(.uvRejected(let retries, _)):
            let choice = try await showFingerprintRetry(retriesRemaining: retries)
            ctx.uvPolicy = (choice == .retryUV) ? .preferred : .skipped
        case .webAuthn(.uvBlocked):
            // The SDK's runExternalUV pivots to PIN automatically when
            // clientPin is configured, so .uvBlocked here generally means
            // no PIN fallback. Cover the with-PIN case in case a future
            // SDK path leaks it.
            if active.hasPin {
                try await showFingerprintLocked()
                ctx.uvPolicy = .skipped
            } else {
                await showInlineFatal(.uvBlockedNoPIN)
                throw error
            }
        case .webAuthn(.pinNotSet):
            try await recoverFromPinNotSet(transport: transport, kind: kind)
        case .webAuthn(.forcePinChange):
            try await recoverFromForcePinChange(transport: transport, kind: kind)
        default:
            throw error
        }
    }

    // MARK: - Transport choice

    /// On iOS, polls the wired loop for up to `wiredDecisionBudget`. If a
    /// wired session lands in that window, go wired; otherwise NFC. macOS
    /// always returns `.wired`. A debounced "Looking for security key…"
    /// panel keeps the user oriented during the wait.
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

        if await transport.isWiredAvailable() { return .wired }

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
    static let wiredDecisionBudget: Duration = .milliseconds(1000)
    #endif

    static let panelDebounceDelay: Duration = .milliseconds(200)

    // MARK: - Per-iteration acquire / close

    private func acquireBodySession(
        transport: any FidoUI.TransportControllerProtocol,
        kind: CeremonyTransport,
        operation: FidoUI.PanelModel.Operation
    ) async throws(FidoUI.Error) -> FidoUI.ActiveSession {
        switch kind {
        case .wired:
            return try await waitForWiredWithPanel(
                transport: transport,
                operation: operation
            )
        case .nfc:
            #if os(iOS)
            let serviceName = model.serviceName
            let alertMessage =
                switch operation {
                case .registration:
                    FidoUI.Strings.nfcAlertCreate(serviceName: serviceName)
                case .authentication:
                    FidoUI.Strings.nfcAlertSignIn(serviceName: serviceName)
                }
            return try await transport.openNFC(alertMessage: alertMessage)
            #else
            // Unreachable: macOS pickCeremonyTransport always returns .wired.
            throw .webAuthn(.internalError("NFC unavailable on macOS", source: .here()))
            #endif
        }
    }

    /// awaitWired with a debounced "waiting for key" panel. Cancel always
    /// shows — the alert window has no system close affordance.
    private func waitForWiredWithPanel(
        transport: any FidoUI.TransportControllerProtocol,
        operation: FidoUI.PanelModel.Operation
    ) async throws(FidoUI.Error) -> FidoUI.ActiveSession {
        if let active = await transport.wired() {
            return active
        }

        let task = Task { @Sendable in
            try await transport.awaitWired()
        }
        let panelTask = Task<Void, Never> { @MainActor [weak self] in
            try? await Task.sleep(for: Self.panelDebounceDelay)
            guard !Task.isCancelled else { return }
            self?.showWaitingForKey(operation: operation) {
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

    /// Drives the iOS NFC system-sheet message: only `.success` writes a
    /// confirmation string before close; `.release` and `.failure` close
    /// silently.
    enum NFCCloseReason: Sendable {
        case release
        case success(operation: FidoUI.PanelModel.Operation)
        case failure
    }

    /// No-op on wired (loop owns the connection across iterations).
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
                    ? FidoUI.Strings.nfcSuccessRegistration
                    : FidoUI.Strings.nfcSuccessAuthentication
            }
        await transport.closeNFC(successMessage: message)
        #endif
    }

}
