import Foundation
import SwiftUI
import YubiKit

func fidoLog(_ tag: String, _ message: @autoclosure () -> String) {
    #if DEBUG
    print("[\(tag)] \(message())")
    #endif
}

/// Entry point for the FIDO2/WebAuthn security-key UI module.
///
/// Owns the full ceremony lifecycle — transport, PIN/UV prompts, error
/// panels, success, cancellation, and setup-recovery (first-time PIN,
/// forced PIN change). On iOS it tries wired (USB-C / Lightning) at
/// ceremony start and falls back to NFC; on macOS it uses HID FIDO.
///
/// Concurrent calls on the same instance are queued — a second ceremony
/// waits for the first to finish rather than racing it for the alert
/// window, the transport, or the shared panel model.
@MainActor
public final class FidoUI {

    private let isPublicSuffix: WebAuthn.PublicSuffixChecker
    private let transportFactory: @MainActor (WebAuthn.Origin) -> any TransportControllerProtocol
    private let model: PanelModel
    private let presenter: Presenter
    private let alertWindow = AlertWindow()

    /// Set while a ceremony is in flight so the host can call `cancel()`
    /// from outside (e.g. WebView teardown).
    private var activeTransport: (any TransportControllerProtocol)?

    private var ceremonyTail: Task<Void, Never>?

    public init(isPublicSuffix: @escaping WebAuthn.PublicSuffixChecker = { _ in false }) {
        self.isPublicSuffix = isPublicSuffix
        self.transportFactory = { origin in
            TransportController(origin: origin, isPublicSuffix: isPublicSuffix)
        }
        self.model = PanelModel()
        self.presenter = Presenter(model: model)
    }

    /// Test seam — `@testable import FidoUI` only.
    init(testTransportFactory: @escaping @MainActor (WebAuthn.Origin) -> any TransportControllerProtocol) {
        self.isPublicSuffix = { _ in false }
        self.transportFactory = testTransportFactory
        self.model = PanelModel()
        self.presenter = Presenter(model: model)
    }

    private func withAlertWindow<R, E>(
        _ body: () async throws(E) -> R
    ) async throws(E) -> R {
        alertWindow.present(model: model)
        defer { alertWindow.dismiss() }
        return try await body()
    }

    /// Aborts the active ceremony, if any. Idempotent. Outer-Task
    /// cancellation of any in-flight call also routes here.
    public func cancel() async {
        presenter.cleanup()
        await activeTransport?.cancel()
    }

    /// Serialize `body` against any other in-flight ceremony on this instance.
    func serialized<R: Sendable>(
        _ body: @MainActor @escaping () async throws(FidoUI.Error) -> R
    ) async throws(FidoUI.Error) -> R {
        let prior = ceremonyTail
        // Typed throws can't ride `Task.failure`, so funnel the outcome
        // through `Result` and unpack at the call boundary.
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
            // workTask is unstructured — route outer-task cancellation through
            // cancel() so the panel awaiter wakes and the transport unwinds.
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
        let name = Self.resolveServiceName(serviceName, options.rp.name, options.rp.id)
        return try await runUICeremony(
            operation: .registration,
            origin: origin,
            serviceName: name
        ) { [presenter = self.presenter] active, ctx, _ throws(FidoUI.Error) in
            try await presenter.handleRegistration(
                makeCredential: { [client = active.client, presenter, ctx] in
                    await client.makeCredential(
                        options,
                        authorization: FidoUI.authorization(ctx, presenter: presenter)
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
        let name = Self.resolveServiceName(serviceName, options.rpId)
        return try await runUICeremony(
            operation: .authentication,
            origin: origin,
            serviceName: name
        ) { [presenter = self.presenter] active, ctx, release throws(FidoUI.Error) in
            try await presenter.handleAuthentication(
                getAssertion: { [client = active.client, presenter, ctx] in
                    await client.getAssertion(options, authorization: FidoUI.authorization(ctx, presenter: presenter))
                },
                rpId: rpId,
                releaseConnection: release
            )
        }
    }

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

    /// First non-empty-after-trimming candidate, or `""`. Empty string makes
    /// the panel header render a service-less variant ("Sign in").
    private static func resolveServiceName(_ candidates: String?...) -> String {
        for candidate in candidates {
            if let trimmed = candidate?.trimmingCharacters(in: .whitespaces), !trimmed.isEmpty {
                return trimmed
            }
        }
        return ""
    }

    /// Per-attempt `Authorization`: rebuilt each iteration so `uvPolicy` /
    /// `pinRetries` reflect any mutation by the outer ceremony catch.
    fileprivate static func authorization(
        _ ctx: FidoUI.Presenter.AttemptContext,
        presenter: FidoUI.Presenter
    ) -> WebAuthn.Authorization {
        WebAuthn.Authorization(
            providePIN: { [presenter, ctx] in
                await presenter.askForPIN(retries: ctx.pinRetries, transport: ctx.transport)
            },
            uv: ctx.uvPolicy
        )
    }
}
