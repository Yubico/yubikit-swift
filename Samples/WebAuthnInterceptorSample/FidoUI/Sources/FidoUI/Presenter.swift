import SwiftUI
import YubiKit

// Panel-layer state and continuation infrastructure. Stream orchestration
// lives in Presenter+Stream.swift; ceremony orchestration in
// Presenter+Ceremony.swift; show* panel methods in Presenter+Panels.swift.

extension FidoUI {
    enum UVRetryChoice: Sendable { case retryUV, usePIN }

    @MainActor
    final class Presenter {

        let model: FidoUI.PanelModel
        /// Resumes the prior awaitPanel continuation with nil when a new
        /// awaitable panel takes over. SDK-cancel closures for
        /// `.waitingForUser` / `.waitingForUserVerification` are captured
        /// directly into the panel cases at install time.
        private var awaitingPanelCanceller: (() -> Void)?

        var lastEnteredPIN: String?

        /// Per-attempt state mutated in place by the catch arms of
        /// `runCeremony` before the next iteration.
        struct AttemptContext: Sendable {
            var transport: CeremonyTransport
            var pinRetries: Int? = nil
            var uvPolicy: WebAuthn.Authorization.UVPolicy = .preferred
        }

        init(model: FidoUI.PanelModel) {
            self.model = model
        }

        func reset() {
            cleanup()
            model.reset()
            lastEnteredPIN = nil
        }

        func updateCachedPIN(_ pin: String?) {
            lastEnteredPIN = pin
        }

        /// Call before installing the first panel — header copy reads
        /// `model.operation`.
        func setCeremonyContext(operation: FidoUI.PanelModel.Operation, serviceName: String) {
            model.operation = operation
            model.serviceName = serviceName
        }

        // MARK: - Panel presentation

        func present() {
            if !model.isPresented { model.isPresented = true }
        }

        func dismiss() {
            model.isPresented = false
        }

        // MARK: - Continuation helpers

        private func setCanceller(_ cancel: @escaping () -> Void) {
            awaitingPanelCanceller?()
            awaitingPanelCanceller = cancel
        }

        /// Returns nil on cancel/cleanup.
        func awaitPanel<T>(
            build: (_ resume: @MainActor @escaping (T?) -> Void) -> FidoUI.PanelModel.Panel
        ) async -> T? {
            await withTaskCancellationHandler {
                await withCheckedContinuation { (continuation: CheckedContinuation<T?, Never>) in
                    let once = MainActorOnce<T?>(continuation: continuation)
                    setCanceller { once(nil) }
                    model.submittingForm = nil
                    model.panel = build { once($0) }
                    present()
                }
            } onCancel: { [weak self] in
                // Outer-task cancel doesn't wake withCheckedContinuation on its
                // own — fire the canceller so the await unwinds.
                Task { @MainActor in
                    self?.awaitingPanelCanceller?()
                }
            }
        }

        /// `dismissOnComplete: false` keeps the window open so the next step
        /// can transition in place; `true` closes it (terminal success).
        func awaitAcknowledgement(
            dismissOnComplete: Bool = false,
            panel: (_ onDismiss: @escaping () -> Void) -> FidoUI.PanelModel.Panel
        ) async {
            _ = await awaitPanel { (resume: @escaping (Void?) -> Void) in
                panel { [weak self] in
                    if dismissOnComplete { self?.dismiss() }
                    resume(())
                }
            }
        }

        /// Does NOT touch `model.panel` / `serviceName` / `isPresented` —
        /// runCeremony installs `showSuccess` after the body returns, and
        /// resetting here would flash a blank panel between them. Use
        /// `reset()` for host-driven teardown.
        func cleanup() {
            awaitingPanelCanceller?()
            awaitingPanelCanceller = nil
            model.submittingForm = nil
        }
    }
}

/// Single-resume guard for a CheckedContinuation. A second `resume(...)`
/// is a runtime precondition violation, so racing paths (button tap vs
/// panel teardown, two button taps) need this gate.
@MainActor
private final class MainActorOnce<T> {
    private var continuation: CheckedContinuation<T, Never>?

    init(continuation: CheckedContinuation<T, Never>) {
        self.continuation = continuation
    }

    func callAsFunction(_ value: sending T) {
        guard let c = continuation else { return }
        continuation = nil
        c.resume(returning: value)
    }
}
