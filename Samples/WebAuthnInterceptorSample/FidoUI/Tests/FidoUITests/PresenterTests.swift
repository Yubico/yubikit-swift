import Testing

@testable import FidoUI
@testable import YubiKit

@Suite("FidoUI.Presenter Tests", .serialized)
@MainActor
struct PresenterTests {

    private func makeUI() -> (FidoUI.Presenter, FidoUI.PanelModel) {
        let model = FidoUI.PanelModel()
        let ui = FidoUI.Presenter(model: model)
        return (ui, model)
    }

    // MARK: - askForPIN

    private enum PINPanelAction: Sendable {
        case submit(String)
        case cancel
    }

    @Test(
        "askForPIN delivers the panel's submit/cancel outcome to the SDK reply",
        arguments: [PINPanelAction.submit("1234"), PINPanelAction.cancel]
    )
    private func askForPINDeliversPanelOutcome(_ action: PINPanelAction) async throws {
        let (ui, model) = makeUI()
        model.serviceName = "test.com"

        let task = Task { @MainActor in
            await ui.askForPIN(retries: nil, transport: .wired)
        }
        await waitForPanel(model, kind: .pin)

        guard case .pin(_, let onSubmit, let onCancel) = model.panel else {
            Issue.record("Expected .pin panel, got \(model.panel.kind)")
            return
        }

        switch action {
        case .submit(let value): onSubmit(value)
        case .cancel: onCancel()
        }

        let reply = await task.value
        switch (action, reply) {
        case (.submit(let expected), .pin(let returned)):
            #expect(returned == expected)
        case (.cancel, .cancel):
            break
        default:
            Issue.record("Action \(action) → unexpected reply \(reply)")
        }
    }

    @Test("askForPIN re-prompts with retries on a second call")
    func askForPINRetry() async throws {
        let (ui, model) = makeUI()
        model.serviceName = "test.com"

        let firstTask = Task { @MainActor in
            await ui.askForPIN(retries: nil, transport: .wired)
        }
        await waitForPanel(model, kind: .pin)
        guard case .pin(let config1, let onSubmit1, _) = model.panel else {
            Issue.record("Expected .pin panel")
            return
        }
        #expect(config1.retries == nil)
        onSubmit1("wrong")
        _ = await firstTask.value

        let secondTask = Task { @MainActor in
            await ui.askForPIN(retries: 5, transport: .wired)
        }
        await waitForPanel(model) { panel in
            if case .pin(let config, _, _) = panel { return config.retries != nil }
            return false
        }
        guard case .pin(let config2, let onSubmit2, _) = model.panel else {
            Issue.record("Expected .pin panel on retry")
            return
        }
        #expect(config2.retries == 5)
        #expect(config2.errorMessage != nil)
        onSubmit2("correct")
        _ = await secondTask.value
    }

    @Test("askForPIN consumes cached PIN on NFC without showing a panel")
    func askForPINReturnsCachedPINOnNFC() async throws {
        let (ui, model) = makeUI()
        model.serviceName = "test.com"
        ui.updateCachedPIN("4242")

        let reply = await ui.askForPIN(retries: 5, transport: .nfc)

        guard case .pin(let value) = reply else {
            Issue.record("Expected .pin reply, got \(reply)")
            return
        }
        #expect(value == "4242")
        #expect(
            model.panel.kind != .pin || !model.isPresented,
            "Cached PIN must be returned without showing the panel"
        )
    }

    // MARK: - collectPrefetchedPIN

    private enum CollectPrefetchedScenario: Sendable {
        case submitNoRetries
        case submitWithRetries
        case cancel
    }

    @Test(
        "collectPrefetchedPIN caches on submit, throws on cancel, surfaces retries",
        arguments: [
            CollectPrefetchedScenario.submitNoRetries,
            CollectPrefetchedScenario.submitWithRetries,
            CollectPrefetchedScenario.cancel,
        ]
    )
    private func collectPrefetchedPINBehavior(_ scenario: CollectPrefetchedScenario) async throws {
        let (ui, model) = makeUI()
        model.serviceName = "test.com"

        let retries: Int? = (scenario == .submitWithRetries) ? 3 : nil
        let task = Task<Void, Error> { @MainActor in
            try await ui.collectPrefetchedPIN(retriesRemaining: retries)
        }
        await waitForPanel(model) { panel in
            if case .pin(let cfg, _, _) = panel { return cfg.retries == retries }
            return false
        }

        guard case .pin(let config, let onSubmit, let onCancel) = model.panel else {
            Issue.record("Expected .pin panel")
            return
        }
        #expect(config.retries == retries)
        if retries != nil {
            #expect(config.errorMessage != nil, "retries != nil must surface the inline error message")
        } else {
            #expect(config.errorMessage == nil)
        }

        switch scenario {
        case .submitNoRetries, .submitWithRetries:
            onSubmit("4242")
            try await task.value
            #expect(
                ui.lastEnteredPIN == "4242",
                "Submit must cache the entered value for the providePIN / showPINEntry path"
            )
        case .cancel:
            onCancel()
            do {
                try await task.value
                Issue.record("Should have thrown .cancelled")
            } catch FidoUI.Error.cancelled {}
        }
    }

    // MARK: - showFingerprintRetry

    @Test("showFingerprintRetry surfaces retries-remaining and returns .retryUV on Try Again")
    func showFingerprintRetryReturnsRetryUVOnRetry() async throws {
        let (ui, model) = makeUI()
        model.serviceName = "test.com"

        let task = Task<FidoUI.UVRetryChoice, Error> { @MainActor in
            try await ui.showFingerprintRetry(retriesRemaining: 3)
        }

        await waitForPanel(model, kind: .fingerprintRetry)

        guard case .fingerprintRetry(_, let retries, let onRetryUV, _, _) = model.panel else {
            Issue.record("Expected .fingerprintRetry panel")
            return
        }
        #expect(retries == 3)
        onRetryUV()

        let result = try await task.value
        #expect(result == .retryUV)
    }

    // MARK: - showFingerprintLocked

    @Test("showFingerprintLocked returns on Use PIN and throws .cancelled on Cancel")
    func showFingerprintLockedHandlesBothChoices() async throws {
        let (ui, model) = makeUI()

        let usePINTask = Task<Void, Error> { @MainActor in
            try await ui.showFingerprintLocked()
        }
        await waitForPanel(model, kind: .fingerprintLocked)
        guard case .fingerprintLocked(let onUsePIN, _) = model.panel else {
            Issue.record("Expected .fingerprintLocked panel")
            return
        }
        onUsePIN()
        try await usePINTask.value

        // Clear between calls — both ceremonies install .fingerprintLocked,
        // so a kind-only wait would race the stale panel.
        model.panel = .processing

        let cancelTask = Task<Void, Error> { @MainActor in
            try await ui.showFingerprintLocked()
        }
        await waitForPanel(model, kind: .fingerprintLocked)
        guard case .fingerprintLocked(_, let onCancel) = model.panel else {
            Issue.record("Expected .fingerprintLocked panel")
            return
        }
        onCancel()
        do {
            try await cancelTask.value
            Issue.record("Should have thrown .cancelled")
        } catch FidoUI.Error.cancelled {}
    }

    // MARK: - retryOnError

    @Test("retryOnError retries after a retryable error")
    func retryOnErrorRetries() async throws {
        let (ui, model) = makeUI()

        let callCount = Box(0)
        let task = Task { @MainActor in
            try await ui.retryOnError { () throws(FidoUI.Error) -> String in
                callCount.value += 1
                if callCount.value == 1 {
                    throw .webAuthn(.timeout(source: .here()))
                }
                return "retried"
            }
        }

        await waitForPanel(model, kind: .error)

        guard case .error(let info, let onRetry, _) = model.panel else {
            Issue.record("Expected .error panel")
            return
        }
        #expect(info.isRetryable)
        #expect(onRetry != nil)

        onRetry?()

        let result = try await task.value
        #expect(result == "retried")
        #expect(callCount.value == 2)
    }

    @Test("retryOnError shows critical-severity panel for pinBlocked, then propagates after dismiss")
    func retryOnErrorPropagatesPinBlocked() async throws {
        let (ui, model) = makeUI()

        let task = Task<String, Error> { @MainActor in
            try await ui.retryOnError { () throws(FidoUI.Error) -> String in
                throw .webAuthn(.pinBlocked(source: .here()))
            }
        }

        await waitForPanel(model, kind: .error)

        guard case .error(let info, _, let onDismiss) = model.panel else {
            Issue.record("Expected .error panel")
            return
        }
        #expect(info.severity == .critical)

        onDismiss()

        do {
            _ = try await task.value
            Issue.record("Should have thrown pinBlocked")
        } catch FidoUI.Error.webAuthn(let error) {
            guard case .pinBlocked = error else {
                Issue.record("Expected pinBlocked, got \(error)")
                return
            }
        }
    }

    /// These errors must bypass the generic Retry/Cancel panel — Retry
    /// would loop the same error and Cancel is counter-intuitive.
    private enum PropagatedError: Sendable, CaseIterable {
        case authenticatorNotAvailable
        case forcePinChange
        case pinNotSet
    }

    @Test(
        "retryOnError propagates non-retryable errors without showing a panel",
        arguments: PropagatedError.allCases
    )
    private func retryOnErrorPropagatesWithoutPanel(_ tag: PropagatedError) async throws {
        let (ui, _) = makeUI()

        let thrown: WebAuthn.ClientError =
            switch tag {
            case .authenticatorNotAvailable: .authenticatorNotAvailable(source: .here())
            case .forcePinChange: .forcePinChange(source: .here())
            case .pinNotSet: .pinNotSet(source: .here())
            }

        do {
            let _: String = try await ui.retryOnError { () throws(FidoUI.Error) in
                throw .webAuthn(thrown)
            }
            Issue.record("Should have thrown")
        } catch FidoUI.Error.webAuthn(let error) {
            // Match by case — the throw-site source location won't match
            // what we constructed.
            switch (tag, error) {
            case (.authenticatorNotAvailable, .authenticatorNotAvailable),
                (.forcePinChange, .forcePinChange),
                (.pinNotSet, .pinNotSet):
                break
            default:
                Issue.record("Expected \(tag), got \(error)")
            }
        }
    }

    // MARK: - Awaitable panel lifecycle

    @Test("Installing a new awaitable panel resumes the prior waiter with nil")
    func setCancellerCollisionResumesPrior() async throws {
        let (ui, model) = makeUI()
        model.serviceName = "test.com"

        let firstTask = Task { @MainActor in
            await ui.showCreatePIN()
        }
        await waitForPanel(model, kind: .createPIN)

        let secondTask = Task { @MainActor in
            await ui.showChangePIN()
        }
        defer { secondTask.cancel() }
        await waitForPanel(model, kind: .changePIN)

        let firstResult = await firstTask.value
        #expect(firstResult == nil, "Prior awaiter must resume with nil when a new awaitable panel arms")

        guard case .changePIN(_, _, let onCancel) = model.panel else {
            Issue.record("Expected .changePIN panel")
            return
        }
        onCancel()
        _ = await secondTask.value
    }

    @Test("Outer task cancellation while a PIN panel is awaiting unwinds the awaiter")
    func awaitPanelHonorsTaskCancellation() async throws {
        let (ui, model) = makeUI()
        model.serviceName = "test.com"

        let task = Task { @MainActor in
            await ui.showCreatePIN()
        }
        await waitForPanel(model, kind: .createPIN)

        task.cancel()

        let result = await task.value
        #expect(result == nil, "Cancelled awaiter must resume with nil instead of hanging")
    }

    /// `cleanup()` must preserve the active panel/presentation flags so
    /// `runCeremony` can install `showSuccess` without flashing a blank panel.
    @Test("cleanup preserves model presentation state but cancels the active awaiter")
    func cleanupPreservesModelStateAndCancelsAwaiter() async throws {
        let (ui, model) = makeUI()
        model.serviceName = "test.com"

        let task = Task { @MainActor in
            await ui.showCreatePIN()
        }
        await waitForPanel(model, kind: .createPIN)

        let panelKindBefore = model.panel.kind
        let serviceNameBefore = model.serviceName
        let isPresentedBefore = model.isPresented

        ui.cleanup()

        #expect(model.panel.kind == panelKindBefore, "cleanup must not swap the panel")
        #expect(model.serviceName == serviceNameBefore, "cleanup must not clear serviceName")
        #expect(model.isPresented == isPresentedBefore, "cleanup must not flip isPresented")

        let result = await task.value
        #expect(result == nil)
    }

    // MARK: - submittingForm lifecycle

    private enum PostSubmitAction: Sendable, CaseIterable {
        case showProcessing
        case showTouchPrompt
        case cleanup
    }

    @Test(
        "PIN submit latches submittingForm; subsequent action either preserves or clears it",
        arguments: PostSubmitAction.allCases
    )
    private func submittingFormLifecycle(_ action: PostSubmitAction) async throws {
        let (ui, model) = makeUI()
        model.serviceName = "test.com"

        let task = Task { @MainActor in
            await ui.askForPIN(retries: nil, transport: .wired)
        }
        await waitForPanel(model, kind: .pin)
        #expect(model.submittingForm == nil, "Form starts in pre-submit state")

        guard case .pin(_, let onSubmit, _) = model.panel else {
            Issue.record("Expected .pin panel")
            return
        }
        onSubmit("4242")
        #expect(model.submittingForm == .pin, "submit must latch submittingForm")

        switch action {
        case .showProcessing:
            ui.showProcessing()
            #expect(model.panel.kind == .pin, "processing must not replace the form panel")
            #expect(model.submittingForm == .pin, "processing must not clear submittingForm")
        case .showTouchPrompt:
            ui.showTouchPrompt(cancel: {})
            await waitForPanel(model, kind: .touch)
            #expect(model.submittingForm == nil, "touch prompt must clear submittingForm")
        case .cleanup:
            ui.cleanup()
            #expect(model.submittingForm == nil, "cleanup must clear submittingForm")
        }

        _ = await task.value
    }
}
