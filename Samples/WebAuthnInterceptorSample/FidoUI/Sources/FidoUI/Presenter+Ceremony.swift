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

    private enum TransportSelection: Sendable {
        case wired
        case nfc
        case cancelled
    }

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
        isPinPrioritized: Bool,
        body: @escaping CeremonyBody<R>
    ) async throws(FidoUI.Error) -> R {
        setCeremonyContext(operation: operation, serviceName: serviceName)
        // Outer wrapper runs cleanup(); a reset() here would clobber the
        // success panel between body return and showSuccess.
        defer {
            updateCachedPIN(nil)
            needsNFCPIN = false
        }

        await transport.start()

        do throws(FidoUI.Error) {
            let kind = try await pickCeremonyTransport(
                transport: transport,
                operation: operation
            )

            // Stop wired discovery after choosing NFC.
            if kind == .nfc {
                guard !Task.isCancelled else { throw .cancelled }
                await transport.stopWiredLoop()
                guard !Task.isCancelled else { throw .cancelled }
                if isPinPrioritized {
                    try await collectPrefetchedPIN(retriesRemaining: nil)
                    guard !Task.isCancelled else { throw .cancelled }
                }
            }

            let releaseConnection: @Sendable () async -> Void = { [weak self, transport, kind] in
                await self?.closeNFCIfNeeded(transport: transport, kind: kind, reason: .release)
            }

            var ctx = FidoUI.Presenter.AttemptContext(transport: kind)
            while true {
                let active: FidoUI.ActiveSession
                do {
                    active = try await acquireBodySession(
                        transport: transport,
                        kind: kind,
                        operation: operation
                    )
                } catch let error {
                    if kind == .nfc,
                        case .webAuthn(.authenticatorNotAvailable(let source)) = error
                    {
                        _ = await showError(.authenticatorNotAvailable(source: source), transport: kind)
                    }
                    throw error
                }
                guard !Task.isCancelled else { throw .cancelled }

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
                    if case .cancelled = error, kind == .nfc, needsNFCPIN, !Task.isCancelled {
                        needsNFCPIN = false
                        await closeNFCIfNeeded(transport: transport, kind: kind, reason: .release)
                        try await collectPrefetchedPIN(retriesRemaining: ctx.pinRetries)
                        continue
                    }
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
        case .webAuthn(.authenticatorNotAvailable(let source)):
            _ = await showError(.authenticatorNotAvailable(source: source), transport: kind)
            throw error
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
            try await recoverFromPinNotSet(
                transport: transport,
                kind: kind,
                minPINLength: active.minPINLength
            )
        case .webAuthn(.forcePinChange):
            try await recoverFromForcePinChange(
                transport: transport,
                kind: kind,
                minPINLength: active.minPINLength
            )
        case .webAuthn(let clientError):
            guard kind == .nfc else { throw error }
            try await handleClientError(clientError)
        default:
            throw error
        }
    }

    // MARK: - Transport choice

    /// Give wired discovery a short head start. Once a connection is opening,
    /// wait for it while allowing the user to choose NFC or cancel.
    private func pickCeremonyTransport(
        transport: any FidoUI.TransportControllerProtocol,
        operation: FidoUI.PanelModel.Operation
    ) async throws(FidoUI.Error) -> CeremonyTransport {
        #if os(iOS)
        let choice = AsyncStream<TransportSelection>.makeStream(bufferingPolicy: .bufferingNewest(1))
        defer { choice.continuation.finish() }
        let useNFC: @Sendable () -> Void = { choice.continuation.yield(.nfc) }
        let waitForUSB: @Sendable () -> Void = { choice.continuation.yield(.wired) }
        let cancel: @Sendable () -> Void = { choice.continuation.yield(.cancelled) }
        let panel = Task { @MainActor [weak self] in
            try? await Task.sleep(for: Self.panelDebounceDelay)
            guard !Task.isCancelled else { return }
            let isConnecting = await transport.isWiredAvailable()
            guard !Task.isCancelled else { return }
            self?.showWaitingForKey(
                operation: operation,
                isConnecting: isConnecting,
                onUseNFC: useNFC,
                onWaitForUSB: waitForUSB,
                onCancel: cancel
            )
        }
        defer { panel.cancel() }

        guard !Task.isCancelled else { throw .cancelled }
        if await transport.wired() != nil {
            guard !Task.isCancelled else { throw FidoUI.Error.cancelled }
            return .wired
        }

        let outcome = await withTaskGroup(of: TransportSelection?.self) { group in
            group.addTask {
                do throws(FidoUI.Error) {
                    _ = try await transport.awaitWired()
                    return .wired
                } catch {
                    if case .cancelled = error { return .cancelled }
                    return .nfc
                }
            }
            group.addTask {
                do {
                    try await Task.sleep(for: Self.wiredDecisionBudget)
                    guard await transport.isWiredAvailable() else { return .nfc }
                    guard !Task.isCancelled else { return .cancelled }
                    await self.showWaitingForKey(
                        operation: operation,
                        isConnecting: true,
                        onUseNFC: useNFC,
                        onWaitForUSB: waitForUSB,
                        onCancel: cancel
                    )
                    return nil
                } catch {
                    return .cancelled
                }
            }
            group.addTask {
                for await selection in choice.stream { return selection }
                return .cancelled
            }
            for await selection in group {
                guard let selection else { continue }
                group.cancelAll()
                return selection
            }
            return .cancelled
        }
        guard !Task.isCancelled else { throw .cancelled }
        switch outcome {
        case .wired: return .wired
        case .nfc: return .nfc
        case .cancelled: throw .cancelled
        }
        #else
        return .wired
        #endif
    }

    #if os(iOS)
    private static let wiredDecisionBudget: Duration = .seconds(3)
    #endif

    private static let panelDebounceDelay: Duration = .milliseconds(200)

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
            return try await openNFC(transport: transport, alertMessage: alertMessage)
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
            guard !Task.isCancelled else { throw FidoUI.Error.cancelled }
            return active
        }

        let task = Task { @Sendable in
            try await transport.awaitWired()
        }
        let panelTask = Task<Void, Never> { @MainActor [weak self] in
            try? await Task.sleep(for: Self.panelDebounceDelay)
            guard !Task.isCancelled else { return }
            let isConnecting = await transport.isWiredAvailable()
            guard !Task.isCancelled else { return }
            self?.showWaitingForKey(
                operation: operation,
                isConnecting: isConnecting,
                onCancel: { task.cancel() }
            )
        }
        defer { panelTask.cancel() }

        do {
            let active = try await withTaskCancellationHandler {
                try await task.value
            } onCancel: {
                task.cancel()
            }
            guard !Task.isCancelled else { throw FidoUI.Error.cancelled }
            return active
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

    #if os(iOS)
    func openNFC(
        transport: any FidoUI.TransportControllerProtocol,
        alertMessage: String
    ) async throws(FidoUI.Error) -> FidoUI.ActiveSession {
        // The system sheet owns interaction until the connection is released.
        model.isNFCActive = true
        do throws(FidoUI.Error) {
            return try await transport.openNFC(alertMessage: alertMessage)
        } catch {
            model.isNFCActive = false
            throw error
        }
    }
    #endif

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
        model.isNFCActive = false
        #endif
    }

}
