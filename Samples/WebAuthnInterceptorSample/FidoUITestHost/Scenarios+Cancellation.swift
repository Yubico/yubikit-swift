import Foundation

@testable import FidoUI
@testable import YubiKit

extension Runner {

    /// User taps Cancel on the PIN panel during authentication → sheet dismisses.
    static func authCancelAtPIN() async -> ScenarioStatus.Outcome {
        let mock = MockWebAuthnBackend()
        mock.onGetInfo = { .stub(clientPin: true, pinUvAuthToken: true) }
        mock.onGetPinRetries = { .init(retries: 8, powerCycleState: false) }
        mock.onGetUVRetries = { 0 }
        mock.onGetPinUVToken = { _, _, _ in
            CTAP2.Token(token: Data(repeating: 0, count: 32), protocolVersion: .v2)
        }
        mock.onGetAssertion = { _ in
            .mocked(.finished(.stub(credentialId: Data([0xAA]))))
        }

        return await runAuthentication(webauthn: mock)
    }

    /// User taps Cancel during PIN entry on registration → sheet dismisses.
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

    /// Two matching credentials → picker appears → user taps Cancel. The
    /// scenario returns `.completed` because user-cancel is a valid endpoint
    /// (per `runGetAssertion`'s `.cancelled` handling).
    static func authCancelAtPicker() async -> ScenarioStatus.Outcome {
        let mock = MockWebAuthnBackend()
        mock.onGetInfo = { .stub(clientPin: false, pinUvAuthToken: false) }
        let credA = Data([0xAA])
        let credB = Data([0xBB])
        let userA = WebAuthn.User.stub(id: Data([1]), name: "alice@example.com", displayName: "Alice")
        let userB = WebAuthn.User.stub(id: Data([2]), name: "bob@example.com", displayName: "Bob")
        mock.onGetAssertion = { _ in
            .mocked(.finished(.stub(credentialId: credA, user: userA, numberOfCredentials: 2)))
        }
        mock.onGetNextAssertion = {
            .mocked(.finished(.stub(credentialId: credB, user: userB)), touchDelay: .zero)
        }

        return await runAuthentication(webauthn: mock, uv: .discouraged)
    }
}
