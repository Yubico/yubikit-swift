import Foundation
import SwiftUI
import YubiKit

/// Module-internal stderr-style logger. Replaces the prior `os.Logger` in
/// the sample so the test host prints land in the same buffer as XCTest
/// output and SwiftUI previews. Production hosts that want structured
/// logging can add their own facade — these calls aren't wired into any
/// public surface.
func fidoLog(_ tag: String, _ message: String) {
    print("[\(tag)] \(message)")
}

/// Entry point for the FIDO2/WebAuthn security-key UI module.
///
/// FidoUI owns the full ceremony lifecycle — connection establishment,
/// PIN/UV prompts, error panels, success, cancellation, and setup-recovery
/// flows (first-time PIN creation, forced PIN change, transport reconnect).
/// It also owns the transport: on iOS it eagerly tries USB-C / Lightning
/// (`WiredSmartCardConnection`) at ceremony start, falling back to NFC
/// when no wired key is attached; on macOS it polls `HIDFIDOConnection`.
/// The host supplies only authentication context (`isPublicSuffix`) and
/// per-ceremony `origin`.
///
/// Use ``makeCredential(_:origin:serviceName:)`` and
/// ``getAssertion(_:origin:serviceName:)`` to run a ceremony with the
/// full UI and recovery flows attached. Concurrent calls on the same
/// instance are queued — a second ceremony waits for the first to
/// finish rather than racing it for the alert window, the transport,
/// or the shared panel model.
@MainActor
public final class FidoUI {

    private let isPublicSuffix: WebAuthn.PublicSuffixChecker
    private let transportFactory: @MainActor (WebAuthn.Origin) -> any TransportControllerProtocol
    private let model: PanelModel
    private let presenter: Presenter
    private let alertWindow = AlertWindow()

    /// Set while a ceremony is in flight so the host can call `cancel()`
    /// from outside (e.g. WebView teardown). Cleared at ceremony exit.
    private var activeTransport: (any TransportControllerProtocol)?

    /// Tail of the per-instance ceremony chain. Each call awaits the
    /// prior tail's completion before running its body and then becomes
    /// the new tail for the next caller. The tail is a `Task<Void, Never>`
    /// fence so the next caller can chain off any outcome (success,
    /// throw, or task-cancelled); result/throw values flow back through
    /// a separate work task funneled via `Result`.
    private var ceremonyTail: Task<Void, Never>?

    public init(isPublicSuffix: @escaping WebAuthn.PublicSuffixChecker = { _ in false }) {
        self.isPublicSuffix = isPublicSuffix
        self.transportFactory = { origin in
            TransportController(origin: origin, isPublicSuffix: isPublicSuffix)
        }
        self.model = PanelModel()
        self.presenter = Presenter(model: model)
    }

    /// Test-only seam: lets the test host inject its own
    /// `TransportControllerProtocol` to drive scenarios without real
    /// hardware. No production code path uses this initializer.
    init(_testTransportFactory: @escaping @MainActor (WebAuthn.Origin) -> any TransportControllerProtocol) {
        self.isPublicSuffix = { _ in false }
        self.transportFactory = _testTransportFactory
        self.model = PanelModel()
        self.presenter = Presenter(model: model)
    }

    /// Open a fresh alert window around `body` and close it on return. Used
    /// by every public entry point so the window lifetime tracks the
    /// ceremony — not the FidoUI instance.
    private func withAlertWindow<R, E>(
        _ body: () async throws(E) -> R
    ) async throws(E) -> R {
        alertWindow.present(model: model)
        defer { alertWindow.dismiss() }
        return try await body()
    }

    /// Aborts the active ceremony (if any). Resumes any panel awaiter so
    /// a parked PIN/picker/error panel unwinds, then closes the active
    /// transport so a blocking NFC/HID open unwinds and pending acquires
    /// are cancelled. Queued ceremonies are not affected — they run
    /// after the active one unwinds. Idempotent / safe to call when no
    /// ceremony is active.
    public func cancel() async {
        presenter.cleanup()
        await activeTransport?.cancel()
    }

    /// Serialize `body` against any other in-flight ceremony on this
    /// instance. Returns once the prior ceremony has completed and
    /// `body` has produced its value (or thrown).
    ///
    /// The new tail is published synchronously before any await, so a
    /// concurrent caller sees the up-to-date chain head and queues
    /// behind us rather than racing.
    ///
    /// Outer-task cancellation is bridged through `cancel()` — a host
    /// that cancels the awaiting Task (e.g. WebView teardown) gets the
    /// same unwind as an explicit `cancel()` call.
    func serialized<R: Sendable>(
        _ body: @MainActor @escaping () async throws(FidoUI.Error) -> R
    ) async throws(FidoUI.Error) -> R {
        let prior = ceremonyTail
        // `Task.failure` is bound at the type level, so typed throws
        // can't ride the Task directly — funnel the outcome through a
        // `Result<R, FidoUI.Error>` and unpack at the call boundary.
        let workTask = Task<Result<R, FidoUI.Error>, Never> { @MainActor in
            await prior?.value
            do throws(FidoUI.Error) {
                return .success(try await body())
            } catch {
                return .failure(error)
            }
        }
        ceremonyTail = Task { @MainActor in _ = await workTask.value }
        let outcome = await withTaskCancellationHandler {
            await workTask.value
        } onCancel: { [weak self] in
            // `workTask` is unstructured and won't see outer-task
            // cancellation on its own. Route through `cancel()` so the
            // panel awaiter wakes up and the transport unwinds — same
            // path a host's explicit `cancel()` would take.
            Task { @MainActor [weak self] in await self?.cancel() }
        }
        switch outcome {
        case .success(let value): return value
        case .failure(let error): throw error
        }
    }
}

extension FidoUI {

    public func makeCredential(
        _ options: WebAuthn.Registration.Options,
        origin: WebAuthn.Origin,
        serviceName: String? = nil
    ) async throws(FidoUI.Error) -> WebAuthn.Registration.Response {
        let name = serviceName ?? options.rp.name ?? options.rp.id
        return try await runUICeremony(
            operation: .registration,
            origin: origin,
            serviceName: name
        ) { [presenter = self.presenter] active, ctx, _ throws(FidoUI.Error) in
            try await presenter.handleRegistration(
                makeCredential: { [client = active.client, presenter, ctx] in
                    await client.makeCredential(
                        options,
                        authorization: authorization(ctx, presenter: presenter)
                    )
                },
                rpId: options.rp.id
            )
        }
    }

    public func getAssertion(
        _ options: WebAuthn.Authentication.Options,
        origin: WebAuthn.Origin,
        serviceName: String? = nil
    ) async throws(FidoUI.Error) -> WebAuthn.Authentication.Response {
        let rpId = options.rpId ?? ""
        let name = serviceName ?? options.rpId ?? String(localized: "YubiKey")
        return try await runUICeremony(
            operation: .authentication,
            origin: origin,
            serviceName: name
        ) { [presenter = self.presenter] active, ctx, release throws(FidoUI.Error) in
            try await presenter.handleAuthentication(
                getAssertion: { [client = active.client, presenter, ctx] in
                    await client.getAssertion(options, authorization: authorization(ctx, presenter: presenter))
                },
                rpId: rpId,
                releaseConnection: release
            )
        }
    }

    /// Shared scaffold for the public ceremony entry points: queue against any
    /// in-flight ceremony, build a fresh transport, expose it for `cancel()`,
    /// open the alert window, and drive `Presenter.runCeremony` with the
    /// caller's body. Public methods only differ in the body and in the
    /// operation/serviceName they hand to the presenter.
    private func runUICeremony<R: Sendable>(
        operation: FidoUI.PanelModel.Operation,
        origin: WebAuthn.Origin,
        serviceName: String,
        body: @escaping FidoUI.Presenter.CeremonyBody<R>
    ) async throws(FidoUI.Error) -> R {
        try await serialized { () async throws(FidoUI.Error) in
            let transport = self.transportFactory(origin)
            self.activeTransport = transport
            defer { self.activeTransport = nil }
            return try await self.withAlertWindow { () throws(FidoUI.Error) in
                try await self.presenter.runCeremony(
                    transport: transport,
                    operation: operation,
                    serviceName: serviceName,
                    body: body
                )
            }
        }
    }
}

/// Builds the `Authorization` for a single ceremony attempt. Captures the
/// attempt's `pinRetries` (next PIN prompt's inline retry message), the
/// committed `transport` (read by `askForPIN` to short-circuit NFC to
/// the cached PIN), and the attempt's `uvPolicy` (toggled by the outer
/// `runCeremony` catch when the user picks "Use PIN" after a UV miss).
@MainActor
private func authorization(
    _ ctx: FidoUI.Presenter.AttemptContext,
    presenter: FidoUI.Presenter
) -> WebAuthn.Authorization {
    WebAuthn.Authorization(
        providePIN: { [weak presenter, ctx] in
            guard let presenter else { return .cancel }
            return await presenter.askForPIN(retries: ctx.pinRetries, transport: ctx.transport)
        },
        uv: ctx.uvPolicy
    )
}
