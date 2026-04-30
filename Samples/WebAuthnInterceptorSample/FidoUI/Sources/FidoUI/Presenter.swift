import SwiftUI
import YubiKit

// Presenter holds the panel-layer state and continuation infrastructure.
// Stream orchestration lives in `Presenter+Stream.swift`; ceremony
// orchestration in `Presenter+Ceremony.swift`; individual `show*` panel
// methods in `Presenter+Panels.swift`.

extension FidoUI {
    @MainActor
    final class Presenter {

        let model: FidoUI.PanelModel
        /// Resumes the prior `awaitPanel` continuation with `nil` when a
        /// new awaitable panel takes over. Fires on swap. SDK-cancel
        /// closures for `.waitingForUser` / `.waitingForUserVerification`
        /// are captured directly into the panel cases at install time —
        /// no parallel slot needed.
        private var awaitingPanelCanceller: (() -> Void)?

        // Ceremony-scoped: cleared by `runCeremony`'s defer on exit.
        var lastEnteredPIN: String?

        /// Per-attempt state carried by `runCeremony` into the body each
        /// iteration. Lives in the loop's local `var`, not on the
        /// presenter — the body captures it by value when building the
        /// `Authorization` closure for that attempt, and the catch arms
        /// mutate it in place before the next iteration.
        struct AttemptContext: Sendable {
            /// Transport the active ceremony committed to. Read by
            /// `askForPIN` to decide between consuming the cached
            /// prefetched PIN (NFC) and showing the inline PIN form
            /// (wired). Set once after `pickCeremonyTransport` and never
            /// changes for the rest of the ceremony.
            var transport: CeremonyTransport
            /// Non-nil after the previous attempt threw `.pinRejected`;
            /// surfaced as the inline "wrong PIN, N attempts left"
            /// message on the next PIN prompt.
            var pinRetries: Int? = nil
            /// `Authorization.uv` for the next attempt. Toggles to
            /// `.skipped` when the user picks "Use PIN" on the
            /// fingerprint-retry panel after a `.uvRejected`.
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

        /// Replaces or invalidates the remembered PIN used for retry pre-fill.
        func updateCachedPIN(_ pin: String?) {
            lastEnteredPIN = pin
        }

        /// Must be called at the start of a ceremony, before the first panel
        /// installs — the waiting/touch panels read `model.operation` for
        /// header copy.
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

        /// Single-slot canceller: when a new awaitable panel arms, the prior
        /// waiter (if any) force-resumes with its cancel value. `cleanup()` flushes
        /// the current one so stale callers never hang.
        private func setCanceller(_ cancel: @escaping () -> Void) {
            awaitingPanelCanceller?()
            awaitingPanelCanceller = cancel
        }

        /// Core await helper: sets `model.panel`, suspends until the panel calls
        /// `resume(value)`, returns nil on cancel/cleanup. `T?` return type means
        /// every panel's cancel path is modeled uniformly as `nil`.
        func awaitPanel<T>(
            build: (_ resume: @MainActor @escaping (T?) -> Void) -> FidoUI.PanelModel.Panel
        ) async -> T? {
            await withTaskCancellationHandler {
                await withCheckedContinuation { (continuation: CheckedContinuation<T?, Never>) in
                    let once = MainActorOnce<T?>(continuation: continuation)
                    setCanceller { once(nil) }
                    // A new awaitable panel always lands the user in a
                    // pre-submit state — clear any prior form's loading flag.
                    model.submittingForm = nil
                    model.panel = build { once($0) }
                    present()
                }
            } onCancel: { [weak self] in
                // Outer-task cancellation (e.g. WebView teardown mid-PIN-entry)
                // doesn't wake `withCheckedContinuation` on its own. Hop to
                // MainActor and fire the same canceller the panel's own Cancel
                // button uses; the unwind (cleanup defer → runCeremony.reset →
                // withAlertWindow.dismiss) handles the rest. Without this the
                // await never returns and the alert window leaks.
                Task { @MainActor in
                    self?.awaitingPanelCanceller?()
                }
            }
        }

        /// Shared helper for single-button acknowledgement panels (Continue/OK).
        ///
        /// `dismissOnComplete: false` (default) leaves the alert window open so
        /// the next ceremony step can transition in place (pinCreated → retry;
        /// pinChanged → retry). `true` closes the window after the user
        /// acknowledges (terminal success panel).
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

        /// Called via `defer` from every public entry point. Does **not** touch
        /// `model.panel` / `serviceName` / `isPresented` — `runCeremony` awaits
        /// `showSuccess` after the body returns, and resetting the model here
        /// would flash a blank-header processing panel between body completion
        /// and the success panel installing. Use `reset()` for host-driven
        /// teardown. Does not touch `lastEnteredPIN` — see the field doc.
        func cleanup() {
            awaitingPanelCanceller?()
            awaitingPanelCanceller = nil
            model.submittingForm = nil
        }
    }
}

/// Ensures the continuation resumes exactly once even when multiple paths
/// race (e.g. button tap vs panel teardown, or two button taps before the
/// first one nils `model.panel`). `CheckedContinuation.resume` is a runtime
/// crash on second invocation, so this guard is load-bearing.
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
