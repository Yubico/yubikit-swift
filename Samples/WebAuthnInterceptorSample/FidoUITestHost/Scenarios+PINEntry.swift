import Foundation

@testable import FidoUI
@testable import YubiKit

extension Runner {

    /// One wrong PIN, then correct. Exercises the inline form re-arm path:
    /// shake animation + cleared field + decremented retry counter, then
    /// successful submission. Counterpart to `flowUVRetryThenSuccess` for
    /// the PIN side — `flowProgressivePINRetries` covers the soft-block
    /// terminal case but not successful recovery.
    static func flowPINRetryThenSuccess() async -> ScenarioStatus.Outcome {
        let attempts = Box(0)
        let correctPIN = "123456"

        let webauthn = MockWebAuthnBackend()
        webauthn.onGetInfo = { .stub(clientPin: true, pinUvAuthToken: true) }
        webauthn.onGetUVRetries = { 0 }
        webauthn.onGetPinRetries = { .init(retries: 8 - attempts.value, powerCycleState: false) }
        webauthn.onGetPinUVToken = {
            (method: CTAP2.ClientPin.Method, _, _) throws(CTAP2.SessionError) -> CTAP2.Token in
            guard case .pin(let pin) = method else {
                throw CTAP2.SessionError.ctapError(.operationDenied, source: .here())
            }
            if pin == correctPIN {
                return CTAP2.Token(token: Data(repeating: 0, count: 32), protocolVersion: .v2)
            }
            attempts.value += 1
            throw CTAP2.SessionError.ctapError(.pinInvalid, source: .here())
        }
        webauthn.onGetAssertion = { _ in
            .mocked(.finished(.stub(credentialId: Data([0xAA]))))
        }

        return await runAuthentication(webauthn: webauthn)
    }

    /// Three wrong PINs in a row trip the CTAP 2.1 soft block (§6.5.5.7):
    /// the first two return `pinInvalid` and decrement the retry counter
    /// (7 → 6 in the UI); the third returns `pinAuthBlocked`, surfacing the
    /// "Remove and reinsert" terminal panel. Mirrors a real YubiKey — once
    /// three consecutive PIN failures occur in one power cycle, no further
    /// PIN attempt is accepted until reinsert.
    static func flowProgressivePINRetries() async -> ScenarioStatus.Outcome {
        let attempts = Box(0)

        let webauthn = MockWebAuthnBackend()
        webauthn.onGetInfo = { .stub(clientPin: true, pinUvAuthToken: true) }
        webauthn.onGetUVRetries = { 0 }
        webauthn.onGetPinRetries = {
            .init(retries: max(0, 8 - attempts.value), powerCycleState: false)
        }
        webauthn.onGetPinUVToken = {
            (method: CTAP2.ClientPin.Method, _, _) throws(CTAP2.SessionError) -> CTAP2.Token in
            guard case .pin = method else {
                throw CTAP2.SessionError.ctapError(.operationDenied, source: .here())
            }
            attempts.value += 1
            if attempts.value >= 3 {
                throw CTAP2.SessionError.ctapError(.pinAuthBlocked, source: .here())
            }
            throw CTAP2.SessionError.ctapError(.pinInvalid, source: .here())
        }
        webauthn.onGetAssertion = { _ in
            .mocked(.finished(.stub(credentialId: Data([0xAA]))))
        }

        return await runAuthentication(webauthn: webauthn)
    }

    /// PIN auth blocked for this power cycle — user must remove and reinsert
    /// the key. Non-retryable critical error panel.
    static func errPINAuthBlocked() async -> ScenarioStatus.Outcome {
        let mock = MockWebAuthnBackend()
        mock.onGetInfo = { .stub(clientPin: true, pinUvAuthToken: true) }
        mock.onGetUVRetries = { 0 }
        mock.onGetPinRetries = { .init(retries: 2, powerCycleState: true) }
        mock.onGetPinUVToken = {
            (_: CTAP2.ClientPin.Method, _, _) throws(CTAP2.SessionError) -> CTAP2.Token in
            throw CTAP2.SessionError.ctapError(.pinAuthBlocked, source: .here())
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
}
