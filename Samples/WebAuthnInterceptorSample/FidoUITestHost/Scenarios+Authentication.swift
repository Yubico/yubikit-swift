import FidoUI
import Foundation

@testable import YubiKit

extension Runner {

    /// UP-only authenticator (no PIN, no UV). Straight to touch → success.
    static func authNoPIN() async -> ScenarioStatus.Outcome {
        let mock = MockWebAuthnBackend()
        mock.onGetInfo = { .stub(clientPin: false, pinUvAuthToken: false) }
        mock.onGetAssertion = { _ in
            .mocked(.finished(.stub(credentialId: Data([0xAA]))))
        }

        return await runAuthentication(webauthn: mock, uv: .discouraged)
    }

    /// User taps Cancel on the PIN panel → sheet dismisses.
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

    /// Validates that the typed PIN actually reaches the backend. The mock
    /// rejects anything other than `expectedPIN`; success implies the PIN
    /// the user typed (in the inline form on macOS, or the prefetch form
    /// on iOS) was forwarded through the `Authorization.providePIN`
    /// closure into `getPinUVTokenUpdates`. Used by the iOS prefetch-PIN
    /// test where reusing `authCancelAtPIN`'s any-PIN-accepts mock would
    /// mask a dropped or replayed value.
    static func authValidatesSubmittedPIN() async -> ScenarioStatus.Outcome {
        let expectedPIN = "123456"
        let mock = MockWebAuthnBackend()
        mock.onGetInfo = { .stub(clientPin: true, pinUvAuthToken: true) }
        mock.onGetPinRetries = { .init(retries: 8, powerCycleState: false) }
        mock.onGetUVRetries = { 0 }
        mock.onGetPinUVToken = {
            (method: CTAP2.ClientPin.Method, _, _) throws(CTAP2.SessionError) -> CTAP2.Token in
            guard case .pin(let pin) = method, pin == expectedPIN else {
                throw CTAP2.SessionError.ctapError(.pinInvalid, source: .here())
            }
            return CTAP2.Token(token: Data(repeating: 0, count: 32), protocolVersion: .v2)
        }
        mock.onGetAssertion = { _ in
            .mocked(.finished(.stub(credentialId: Data([0xAA]))))
        }

        return await runAuthentication(webauthn: mock)
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

    /// Authenticator has no matching credentials → `.noCredentials` error.
    static func authNoCredentials() async -> ScenarioStatus.Outcome {
        let mock = MockWebAuthnBackend()
        mock.onGetInfo = { .stub(clientPin: false, pinUvAuthToken: false) }
        mock.onGetAssertion = { _ in
            .mocked(error: .ctapError(.noCredentials, source: .here()))
        }

        return await runAuthentication(webauthn: mock, uv: .discouraged)
    }
}
