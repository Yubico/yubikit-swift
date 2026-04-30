// Verification flows: PIN retry, UV retry, fallback, decline, and the
// streaming touch-required scenario. These exercise the per-attempt
// `Authorization` PIN/UV path (one-shot SDK calls re-driven by the
// outer ceremony loop on `.pinRejected` / `.uvRejected`), not the
// outer `runCeremony` setup-recovery catch.

import Foundation

@testable import FidoUI
@testable import YubiKit

extension Runner {

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

    /// Authenticator emits `.processing` then `.waitingForUser` mid-stream
    /// before `.finished` — exercises the in-app `.processing` and `.touch`
    /// panels which are otherwise never reached because the other scenarios
    /// emit `.finished` immediately. The default `.mocked` helper already
    /// spaces yields with `.processing` (400 ms) → `.waitingForUser` →
    /// touchDelay → terminal — long enough for both panels to install
    /// and be observable.
    static func flowTouchRequired() async -> ScenarioStatus.Outcome {
        let mock = MockWebAuthnBackend()
        mock.onGetInfo = { .stub(clientPin: false, pinUvAuthToken: false) }
        mock.onMakeCredential = { _ in
            .mocked(.finished(.stub(credentialId: Data([0xAA]))), touchDelay: .milliseconds(600))
        }

        return await runRegistration(webauthn: mock, uv: .discouraged)
    }
}
