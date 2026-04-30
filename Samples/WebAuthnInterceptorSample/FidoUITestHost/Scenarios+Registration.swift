import FidoUI
import Foundation

@testable import YubiKit

extension Runner {

    /// User taps Cancel during PIN entry → sheet dismisses.
    static func regCancelAtPIN() async -> ScenarioStatus.Outcome {
        let mock = MockWebAuthnBackend()
        mock.onGetInfo = { .stub(clientPin: true, pinUvAuthToken: true) }
        mock.onGetPinRetries = { .init(retries: 8, powerCycleState: false) }
        mock.onGetUVRetries = { 0 }
        mock.onGetPinUVToken = { _, _, _ in
            CTAP2.Token(token: Data(repeating: 0, count: 32), protocolVersion: .v2)
        }
        mock.onMakeCredential = { _ in
            .mocked(.finished(.stub(credentialId: Data([0xAA]))))
        }

        return await runRegistration(webauthn: mock)
    }

    /// Authenticator rejects: a passkey already exists for this user.
    static func regCredentialExcluded() async -> ScenarioStatus.Outcome {
        let mock = MockWebAuthnBackend()
        mock.onGetInfo = { .stub(clientPin: false, pinUvAuthToken: false) }
        mock.onMakeCredential = { _ in
            .mocked(error: .ctapError(.credentialExcluded, source: .here()))
        }

        return await runRegistration(webauthn: mock, uv: .discouraged)
    }
}
