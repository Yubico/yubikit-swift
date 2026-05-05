import Foundation

@testable import FidoUI
@testable import YubiKit

extension Runner {

    /// Two UV misses with decrementing retry count, then the third attempt
    /// succeeds. Each miss transitions `.fingerprint` → `.fingerprintRetry`
    /// → user taps Try Again → back to `.fingerprint`.
    static func flowUVRetryThenSuccess() async -> ScenarioStatus.Outcome {
        let uvAttempts = Box(0)

        let webauthn = MockWebAuthnBackend()
        webauthn.onGetInfo = {
            .stub(clientPin: true, userVerification: true, pinUvAuthToken: true)
        }
        webauthn.onGetPinRetries = { .init(retries: 8, powerCycleState: false) }
        webauthn.onGetUVRetries = { 3 - uvAttempts.value }
        webauthn.onGetPinUVToken = {
            (method: CTAP2.ClientPin.Method, _, _) throws(CTAP2.SessionError) -> CTAP2.Token in
            guard case .uv = method else {
                throw CTAP2.SessionError.ctapError(.operationDenied, source: .here())
            }
            if uvAttempts.value >= 2 {
                return CTAP2.Token(token: Data(repeating: 0, count: 32), protocolVersion: .v2)
            }
            uvAttempts.value += 1
            throw CTAP2.SessionError.ctapError(.uvInvalid, source: .here())
        }
        webauthn.onGetAssertion = { _ in
            .mocked(.finished(.stub(credentialId: Data([0xAA]))))
        }

        return await runAuthentication(webauthn: webauthn)
    }

    /// UV fails repeatedly until the authenticator reports 0 retries. SDK
    /// surfaces `.uvBlocked` to FidoUI; the locked panel acknowledges the
    /// state with a "Use PIN" / Cancel choice (no auto-fallback — the user
    /// sees an explicit "sensor locked" moment). User sees fingerprint →
    /// retry(2) → retry(1) → fingerprintLocked → Use PIN → correct PIN →
    /// success.
    static func flowUVExhaustionPINFallback() async -> ScenarioStatus.Outcome {
        let uvAttempts = Box(0)

        let webauthn = MockWebAuthnBackend()
        webauthn.onGetInfo = {
            .stub(clientPin: true, userVerification: true, pinUvAuthToken: true)
        }
        webauthn.onGetPinRetries = { .init(retries: 8, powerCycleState: false) }
        webauthn.onGetUVRetries = { max(0, 3 - uvAttempts.value) }
        webauthn.onGetPinUVToken = {
            (method: CTAP2.ClientPin.Method, _, _) throws(CTAP2.SessionError) -> CTAP2.Token in
            switch method {
            case .uv:
                uvAttempts.value += 1
                throw CTAP2.SessionError.ctapError(.uvInvalid, source: .here())
            case .pin:
                return CTAP2.Token(token: Data(repeating: 0, count: 32), protocolVersion: .v2)
            }
        }
        webauthn.onGetAssertion = { _ in
            .mocked(.finished(.stub(credentialId: Data([0xAA]))))
        }

        return await runAuthentication(webauthn: webauthn)
    }

    /// One UV miss → user taps "Use PIN Instead" on the retry panel. The
    /// next ceremony attempt's `Authorization.uv` switches to `.skipped`
    /// so the SDK goes straight to the PIN closure — note NO additional
    /// UV retry is consumed by the user's decline. User enters PIN →
    /// success.
    static func flowUVDeclineToPIN() async -> ScenarioStatus.Outcome {
        let webauthn = MockWebAuthnBackend()
        webauthn.onGetInfo = {
            .stub(clientPin: true, userVerification: true, pinUvAuthToken: true)
        }
        webauthn.onGetUVRetries = { 2 }
        webauthn.onGetPinRetries = { .init(retries: 8, powerCycleState: false) }
        webauthn.onGetPinUVToken = {
            (method: CTAP2.ClientPin.Method, _, _) throws(CTAP2.SessionError) -> CTAP2.Token in
            switch method {
            case .uv:
                throw CTAP2.SessionError.ctapError(.uvInvalid, source: .here())
            case .pin:
                return CTAP2.Token(token: Data(repeating: 0, count: 32), protocolVersion: .v2)
            }
        }
        webauthn.onGetAssertion = { _ in
            .mocked(.finished(.stub(credentialId: Data([0xAA]))))
        }

        return await runAuthentication(webauthn: webauthn)
    }

    /// UV-only authenticator (no PIN configured). UV misses exhaust retries;
    /// Client has no PIN fallback → throws `.uvBlocked` → Presenter shows the
    /// "Fingerprint Sensor Locked" inline fatal panel (non-retryable).
    static func errUVBlocked() async -> ScenarioStatus.Outcome {
        let uvAttempts = Box(0)
        let mock = MockWebAuthnBackend()
        mock.onGetInfo = {
            .stub(clientPin: false, userVerification: true, pinUvAuthToken: true)
        }
        mock.onGetUVRetries = { max(0, 3 - uvAttempts.value) }
        mock.onGetPinUVToken = {
            (_: CTAP2.ClientPin.Method, _, _) throws(CTAP2.SessionError) -> CTAP2.Token in
            uvAttempts.value += 1
            throw CTAP2.SessionError.ctapError(.uvInvalid, source: .here())
        }
        mock.onGetAssertion = { _ in
            .mocked(.finished(.stub(credentialId: Data([0xAA]))))
        }

        return await runAuthentication(webauthn: mock)
    }
}
