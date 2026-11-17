import Foundation
import SwiftUI
import YubiKit

#if os(iOS)
import UIKit
#elseif os(macOS)
import AppKit
#endif

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
/// ceremony start and falls back to NFC; macOS uses HID FIDO.
///
/// Only one ceremony can run on an instance at a time. Overlapping calls
/// fail with `Error.operationInProgress`.
@MainActor
public final class FidoUI {

    #if os(iOS)
    public typealias PresentationAnchor = UIWindow
    #elseif os(macOS)
    public typealias PresentationAnchor = NSWindow
    #endif

    private let presentationAnchor: @MainActor @Sendable () -> PresentationAnchor?
    private let isPinPrioritized: Bool
    private let transportFactory: @MainActor (WebAuthn.Origin) -> any TransportControllerProtocol
    private let model: PanelModel
    private let presenter: Presenter
    private let alertWindow = AlertWindow()

    /// Set while a ceremony is in flight so the host can call `cancel()`
    /// from outside (e.g. WebView teardown).
    private var activeTransport: (any TransportControllerProtocol)?

    private var activeCeremony: (id: UUID, cancel: @MainActor () async -> Void)?

    /// Creates a UI for security-key ceremonies.
    ///
    /// - Parameters:
    ///   - presentationAnchor: Resolves the initiating view's window when a
    ///     ceremony starts. Return nil if the view is no longer attached.
    ///     Capture the view weakly to avoid retaining its owner.
    ///   - isPinPrioritized: On iOS, ask for a PIN before scanning over NFC.
    ///     The default is to scan first and ask only if a PIN is needed.
    ///   - isPublicSuffix: Checks relying-party identifiers against a Public
    ///     Suffix List.
    public init(
        presentationAnchor: @escaping @MainActor @Sendable () -> PresentationAnchor?,
        isPinPrioritized: Bool = false,
        isPublicSuffix: @escaping WebAuthn.PublicSuffixChecker
    ) {
        self.presentationAnchor = presentationAnchor
        self.isPinPrioritized = isPinPrioritized
        self.transportFactory = { origin in
            TransportController(origin: origin, isPublicSuffix: isPublicSuffix)
        }
        self.model = PanelModel()
        self.presenter = Presenter(model: model)
    }

    /// Test seam — `@testable import FidoUI` only.
    init(
        presentationAnchor: @escaping @MainActor @Sendable () -> PresentationAnchor? = { nil },
        isPinPrioritized: Bool = false,
        testTransportFactory: @escaping @MainActor (WebAuthn.Origin) -> any TransportControllerProtocol
    ) {
        self.presentationAnchor = presentationAnchor
        self.isPinPrioritized = isPinPrioritized
        self.transportFactory = testTransportFactory
        self.model = PanelModel()
        self.presenter = Presenter(model: model)
    }

    private func withAlertWindow<R>(
        _ body: () async throws(FidoUI.Error) -> R
    ) async throws(FidoUI.Error) -> R {
        try alertWindow.present(model: model, anchor: presentationAnchor())
        defer { alertWindow.dismiss() }
        return try await body()
    }

    /// Cancels the active ceremony and waits for its teardown.
    /// Cancelling the caller's task also cancels its ceremony.
    public func cancel() async {
        await activeCeremony?.cancel()
    }

    func performCeremony<R: Sendable>(
        _ body: @MainActor @escaping () async throws(FidoUI.Error) -> R
    ) async throws(FidoUI.Error) -> R {
        guard !Task.isCancelled else { throw .cancelled }
        guard activeCeremony == nil else { throw .operationInProgress }

        let id = UUID()
        let workTask = Task<Result<R, FidoUI.Error>, Never> { @MainActor in
            defer {
                self.activeCeremony = nil
                self.presenter.cancelSubmittedForm = nil
            }
            do throws(FidoUI.Error) {
                guard !Task.isCancelled else { throw .cancelled }
                let result = try await body()
                guard !Task.isCancelled else { throw .cancelled }
                return .success(result)
            } catch {
                return .failure(Task.isCancelled ? .cancelled : error)
            }
        }
        activeCeremony = (
            id,
            { [weak self] in
                workTask.cancel()
                self?.presenter.cleanup()
                await self?.activeTransport?.cancel()
                _ = await workTask.value
            }
        )
        let cancelRequest: @Sendable () -> Void = { [weak self] in
            workTask.cancel()
            Task { @MainActor [weak self] in
                await self?.cancel(requestID: id)
            }
        }
        presenter.cancelSubmittedForm = cancelRequest
        let outcome = await withTaskCancellationHandler {
            await workTask.value
        } onCancel: {
            cancelRequest()
        }
        switch outcome {
        case .success(let value): return value
        case .failure(let error): throw error
        }
    }

    private func cancel(requestID: UUID) async {
        guard let activeCeremony, activeCeremony.id == requestID else { return }
        await activeCeremony.cancel()
    }
}

extension FidoUI {

    /// Creates a credential on the authenticator. The relying party must verify
    /// and store the returned response to complete registration.
    ///
    /// `serviceName` is display text only. The origin and relying-party ID
    /// determine which site can use the credential.
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

    /// Obtains a signed assertion. The relying party must verify the returned
    /// response before treating the user as signed in.
    ///
    /// `serviceName` is display text only. The origin and relying-party ID
    /// determine which site can use the credential.
    public func getAssertion(
        _ options: WebAuthn.Authentication.Options,
        origin: WebAuthn.Origin,
        serviceName: String? = nil
    ) async throws(FidoUI.Error) -> WebAuthn.Authentication.Response {
        let rpId = options.rpId ?? origin.host
        let name = Self.resolveServiceName(serviceName, options.rpId, origin.host)
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
        try await performCeremony { () async throws(FidoUI.Error) in
            let transport = self.transportFactory(origin)
            self.activeTransport = transport
            defer { self.activeTransport = nil }
            return try await self.withAlertWindow { () throws(FidoUI.Error) in
                try await self.presenter.runCeremony(
                    transport: transport,
                    operation: operation,
                    serviceName: serviceName,
                    isPinPrioritized: self.isPinPrioritized,
                    body: body
                )
            }
        }
    }

    /// First non-empty-after-trimming candidate, or `""`. Empty string makes
    /// the panel header render a service-less variant ("Sign in").
    private static func resolveServiceName(_ candidates: String?...) -> String {
        for candidate in candidates {
            if let trimmed = candidate?.trimmingCharacters(in: .whitespacesAndNewlines), !trimmed.isEmpty {
                return trimmed
            }
        }
        return ""
    }

    /// Per-attempt `Authorization`: rebuilt each iteration so `uvPolicy` /
    /// `pinRetries` reflect any mutation by the outer ceremony catch.
    private static func authorization(
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
