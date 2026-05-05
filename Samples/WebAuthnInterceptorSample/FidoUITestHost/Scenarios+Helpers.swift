// Shared option builders and ceremony drivers used across scenario files.

import FidoUI
import Foundation

@testable import YubiKit

/// Reference-typed state container so captured closures can mutate shared
/// state across the flow. Used by scenarios where mock behavior evolves as
/// the user progresses (e.g. PIN being set, retry counters decrementing).
final class Box<T>: @unchecked Sendable {
    var value: T
    init(_ value: T) { self.value = value }
}

extension Runner {

    static func regOptions(
        uv: WebAuthn.UserVerificationPreference = .required
    ) -> WebAuthn.Registration.Options {
        WebAuthn.Registration.Options(
            challenge: Data(repeating: 0x02, count: 32),
            rp: .init(id: "example.com", name: "example.com"),
            user: .init(id: Data([0xFF]), name: "user@example.com", displayName: "User"),
            userVerification: uv
        )
    }

    static func authOptions(
        uv: WebAuthn.UserVerificationPreference = .required
    ) -> WebAuthn.Authentication.Options {
        WebAuthn.Authentication.Options(
            challenge: Data(repeating: 0x01, count: 32),
            rpId: "example.com",
            userVerification: uv
        )
    }

    /// Builds a FidoUI against the standard mock transport and runs a
    /// registration ceremony with `regOptions(uv:)`.
    static func runRegistration(
        webauthn: MockWebAuthnBackend,
        pinSetup: MockPINSetupBackend = MockPINSetupBackend(),
        uv: WebAuthn.UserVerificationPreference = .required
    ) async -> ScenarioStatus.Outcome {
        let fido = makeMockedFidoUI(webauthn: webauthn, pinSetup: pinSetup)
        return await runMakeCredential(fido, options: regOptions(uv: uv), serviceName: "example.com")
    }

    /// Builds a FidoUI against the standard mock transport and runs an
    /// authentication ceremony with `authOptions(uv:)`.
    static func runAuthentication(
        webauthn: MockWebAuthnBackend,
        pinSetup: MockPINSetupBackend = MockPINSetupBackend(),
        uv: WebAuthn.UserVerificationPreference = .required
    ) async -> ScenarioStatus.Outcome {
        let fido = makeMockedFidoUI(webauthn: webauthn, pinSetup: pinSetup)
        return await runGetAssertion(fido, options: authOptions(uv: uv), serviceName: "example.com")
    }
}
