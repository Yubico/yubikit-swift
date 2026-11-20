import FidoUI
import Foundation
import YubiKit

private func log(_ message: @autoclosure () -> String) {
    #if DEBUG
    print("[WebAuthnHandler] \(message())")
    #endif
}

/// `@MainActor` because FidoUI itself is `@MainActor` and the handler's
/// only state is the FidoUI instance — there's no mutable connection
/// state on the handler since FidoUI now owns the transport lifecycle.
@MainActor
final class WebAuthnHandler {

    // TODO: Add PublicSuffixList integration.
    private let isPublicSuffix: WebAuthn.PublicSuffixChecker = { _ in false }

    /// FidoUI owns the connection lifecycle (eager wired open, lazy NFC,
    /// HID polling on macOS). One instance is reused across ceremonies;
    /// origin is passed per-call.
    private let fidoUI: FidoUI

    init(presentationAnchor: @escaping @MainActor @Sendable () -> FidoUI.PresentationAnchor?) {
        self.fidoUI = FidoUI(
            presentationAnchor: presentationAnchor,
            isPublicSuffix: self.isPublicSuffix
        )
    }

    /// Aborts any in-flight ceremony. WebView calls this on dismiss /
    /// new-message arrival to close any open transport so a blocking
    /// NFC/HID open unwinds before the next ceremony starts.
    func cancelActiveCeremony() async {
        log("cancelActiveCeremony")
        await fidoUI.cancel()
    }

    func handleCreate(_ data: Data, origin: WebAuthn.Origin) async throws -> String {
        let options = try JSONDecoder().decode(
            WebAuthn.Registration.Options.self,
            from: data
        )
        log("handleCreate origin=\(origin) rp=\(options.rp.id)")
        do {
            let response = try await fidoUI.makeCredential(
                options,
                origin: origin,
                serviceName: origin.host
            )
            log("handleCreate succeeded")
            return String(decoding: try response.toJSON(), as: UTF8.self)
        } catch {
            log("handleCreate failed: \(error)")
            throw error
        }
    }

    func handleGet(_ data: Data, origin: WebAuthn.Origin) async throws -> String {
        let options = try JSONDecoder().decode(
            WebAuthn.Authentication.Options.self,
            from: data
        )
        log("handleGet origin=\(origin) rpId=\(options.rpId ?? "<none>")")
        do {
            let response = try await fidoUI.getAssertion(
                options,
                origin: origin,
                serviceName: origin.host
            )
            log("handleGet succeeded")
            return String(decoding: try response.toJSON(), as: UTF8.self)
        } catch {
            log("handleGet failed: \(error)")
            throw error
        }
    }
}
