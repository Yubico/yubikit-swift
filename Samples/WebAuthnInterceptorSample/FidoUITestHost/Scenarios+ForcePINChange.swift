import Foundation

@testable import FidoUI
@testable import YubiKit

extension Runner {

    /// Authenticator has a PIN set but forcePinChange is true. The SDK
    /// throws `.forcePinChange` from `acquireAuthToken` before prompting
    /// for a PIN; FidoUI's catch arm dispatches the changePIN flow — no
    /// wasted PIN entry. After `pinSetup.changePIN` flips the mock, the
    /// next iteration's `getInfo` reports `forcePinChange: false` and the
    /// ceremony succeeds.
    static func flowForcePinChange() async -> ScenarioStatus.Outcome {
        let changed = Box(false)

        let webauthn = MockWebAuthnBackend()
        webauthn.onGetInfo = {
            .stub(clientPin: true, pinUvAuthToken: true, forcePinChange: !changed.value)
        }
        webauthn.onGetPinRetries = { .init(retries: 8, powerCycleState: false) }
        webauthn.onGetUVRetries = { 0 }
        webauthn.onGetPinUVToken = {
            (method: CTAP2.ClientPin.Method, _, _) throws(CTAP2.SessionError) -> CTAP2.Token in
            guard case .pin = method else {
                throw CTAP2.SessionError.ctapError(.operationDenied, source: .here())
            }
            if !changed.value {
                // Defense-in-depth: the SDK's upfront check should throw
                // `.forcePinChange` before reaching getPinUVToken. If it
                // doesn't, fail fast with pinInvalid rather than silently
                // returning a token.
                throw CTAP2.SessionError.ctapError(.pinInvalid, source: .here())
            }
            return CTAP2.Token(token: Data(repeating: 0, count: 32), protocolVersion: .v2)
        }
        webauthn.onGetAssertion = { _ in
            .mocked(.finished(.stub(credentialId: Data([0xAA]))))
        }

        let pinSetup = MockPINSetupBackend()
        pinSetup.onChangePIN = { _, _ in changed.value = true }

        return await runAuthentication(webauthn: webauthn, pinSetup: pinSetup)
    }

    /// Force-PIN-change with a complexity rejection on the first new PIN.
    /// Verifies the current-PIN field stays pre-filled across the
    /// `pinPolicyViolation` retry — without that, the user would have to
    /// re-type the original PIN they already entered.
    static func flowForcePinChangeComplexityThenSuccess() async -> ScenarioStatus.Outcome {
        let changed = Box(false)
        let changePINAttempts = Box(0)

        let webauthn = MockWebAuthnBackend()
        webauthn.onGetInfo = {
            .stub(clientPin: true, pinUvAuthToken: true, forcePinChange: !changed.value)
        }
        webauthn.onGetPinRetries = { .init(retries: 8, powerCycleState: false) }
        webauthn.onGetUVRetries = { 0 }
        webauthn.onGetPinUVToken = {
            (method: CTAP2.ClientPin.Method, _, _) throws(CTAP2.SessionError) -> CTAP2.Token in
            guard case .pin = method else {
                throw CTAP2.SessionError.ctapError(.operationDenied, source: .here())
            }
            if !changed.value {
                throw CTAP2.SessionError.ctapError(.pinInvalid, source: .here())
            }
            return CTAP2.Token(token: Data(repeating: 0, count: 32), protocolVersion: .v2)
        }
        webauthn.onGetAssertion = { _ in
            .mocked(.finished(.stub(credentialId: Data([0xAA]))))
        }

        let pinSetup = MockPINSetupBackend()
        pinSetup.onChangePIN = { _, _ in
            changePINAttempts.value += 1
            if changePINAttempts.value == 1 {
                throw CTAP2.SessionError.ctapError(.pinPolicyViolation, source: .here())
            }
            changed.value = true
        }

        return await runAuthentication(webauthn: webauthn, pinSetup: pinSetup)
    }

    /// Force-PIN-change where the user mistypes the current PIN on the first
    /// attempt. `changePIN` throws `pinInvalid` → `classifySetupError` re-arms
    /// the form with "The current PIN is incorrect."; the second attempt with
    /// the correct current PIN succeeds. Regression target for the
    /// `pinInvalid` branch in `SetupRecovery.classifySetupError`.
    static func flowForcePinChangeWrongCurrent() async -> ScenarioStatus.Outcome {
        let changed = Box(false)
        let changePINAttempts = Box(0)

        let webauthn = MockWebAuthnBackend()
        webauthn.onGetInfo = {
            .stub(clientPin: true, pinUvAuthToken: true, forcePinChange: !changed.value)
        }
        webauthn.onGetPinRetries = { .init(retries: 8, powerCycleState: false) }
        webauthn.onGetUVRetries = { 0 }
        webauthn.onGetPinUVToken = {
            (method: CTAP2.ClientPin.Method, _, _) throws(CTAP2.SessionError) -> CTAP2.Token in
            guard case .pin = method else {
                throw CTAP2.SessionError.ctapError(.operationDenied, source: .here())
            }
            if !changed.value {
                throw CTAP2.SessionError.ctapError(.pinInvalid, source: .here())
            }
            return CTAP2.Token(token: Data(repeating: 0, count: 32), protocolVersion: .v2)
        }
        webauthn.onGetAssertion = { _ in
            .mocked(.finished(.stub(credentialId: Data([0xAA]))))
        }

        let pinSetup = MockPINSetupBackend()
        pinSetup.onChangePIN = { _, _ in
            changePINAttempts.value += 1
            if changePINAttempts.value == 1 {
                throw CTAP2.SessionError.ctapError(.pinInvalid, source: .here())
            }
            changed.value = true
        }

        return await runAuthentication(webauthn: webauthn, pinSetup: pinSetup)
    }
}
