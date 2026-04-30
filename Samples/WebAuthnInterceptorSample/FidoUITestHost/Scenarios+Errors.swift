import FidoUI
import Foundation

@testable import YubiKit

extension Runner {

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

    /// Setup recovery hits a permanent host-side error: the user reaches the
    /// createPIN form (via `.pinNotSet`) and the host's `setPIN` closure
    /// throws a non-CTAP error. Must surface as an inline-fatal error panel
    /// rather than re-arming the createPIN form on a generic "try again."
    static func errSetupPermanentFailure() async -> ScenarioStatus.Outcome {
        let mock = MockWebAuthnBackend()
        mock.onGetInfo = {
            .stub(clientPin: false, userVerification: true, pinUvAuthToken: true)
        }
        mock.onGetPinRetries = { .init(retries: 8, powerCycleState: false) }
        mock.onGetUVRetries = { 0 }
        mock.onGetPinUVToken = {
            (_: CTAP2.ClientPin.Method, _, _) throws(CTAP2.SessionError) -> CTAP2.Token in
            throw CTAP2.SessionError.ctapError(.pinNotSet, source: .here())
        }
        mock.onMakeCredential = { _ in
            .mocked(.finished(.stub(credentialId: Data([0xAA]))))
        }

        let pinSetup = MockPINSetupBackend()
        pinSetup.onSetPIN = { _ in
            struct SimulatedHostFailure: Error {}
            throw SimulatedHostFailure()
        }

        return await runRegistration(webauthn: mock, pinSetup: pinSetup)
    }
}
