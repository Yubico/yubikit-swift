import Foundation

@testable import FidoUI
@testable import YubiKit

extension Runner {

    /// Authenticator has no matching credentials → `.noCredentials` error.
    static func authNoCredentials() async -> ScenarioStatus.Outcome {
        let mock = MockWebAuthnBackend()
        mock.onGetInfo = { .stub(clientPin: false, pinUvAuthToken: false) }
        mock.onGetAssertion = { _ in
            .mocked(error: .ctapError(.noCredentials, source: .here()))
        }

        return await runAuthentication(webauthn: mock, uv: .discouraged)
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
