import Foundation

@testable import FidoUI
@testable import YubiKit

extension Runner {

    /// YubiKey Bio with a fingerprint enrolled but no PIN configured — UV
    /// works but has no fallback. RP requires UV; `getUVRetries` reports 0
    /// (all UV blocked / no enrolled finger in this simulated state).
    /// Client falls to the PIN path and sees `clientPin == false` → throws
    /// `.pinNotSet`. FidoUI catches → createPIN → `pinSetup.setPIN` →
    /// reconnect → ceremony retries → PIN accepted → success.
    static func flowFirstTimeSetup() async -> ScenarioStatus.Outcome {
        let pinSet = Box(false)

        let webauthn = MockWebAuthnBackend()
        webauthn.onGetInfo = {
            .stub(
                clientPin: pinSet.value,
                userVerification: true,
                pinUvAuthToken: true
            )
        }
        webauthn.onGetPinRetries = { .init(retries: 8, powerCycleState: false) }
        // 0 UV retries: Client skips UV loop → falls to PIN check.
        webauthn.onGetUVRetries = { 0 }
        webauthn.onGetPinUVToken = {
            (_: CTAP2.ClientPin.Method, _, _) throws(CTAP2.SessionError) -> CTAP2.Token in
            guard pinSet.value else {
                // Shouldn't be called before setPIN since Client throws
                // pinNotSet before reaching this. Keep as safety net.
                throw CTAP2.SessionError.ctapError(.pinNotSet, source: .here())
            }
            return CTAP2.Token(token: Data(repeating: 0, count: 32), protocolVersion: .v2)
        }
        webauthn.onMakeCredential = { _ in
            .mocked(.finished(.stub(credentialId: Data([0xAA]))))
        }

        let pinSetup = MockPINSetupBackend()
        pinSetup.onSetPIN = { _ in pinSet.value = true }

        return await runRegistration(webauthn: webauthn, pinSetup: pinSetup)
    }

    /// Setup-recovery's `applySetup` opens a fresh session for `setPIN`. If
    /// the session-acquire throws a transient transport error, `applySetup`
    /// returns `.retry(message: "Failed to connect…")` and the createPIN form
    /// re-arms with the message. Second attempt succeeds, ceremony retries
    /// on the post-recovery loop, and the credential is created.
    static func flowSetupTransientConnectFail() async -> ScenarioStatus.Outcome {
        let pinSet = Box(false)
        let acquireAttempts = Box(0)

        let webauthn = MockWebAuthnBackend()
        webauthn.onGetInfo = {
            .stub(clientPin: pinSet.value, userVerification: true, pinUvAuthToken: true)
        }
        webauthn.onGetPinRetries = { .init(retries: 8, powerCycleState: false) }
        webauthn.onGetUVRetries = { 0 }
        webauthn.onGetPinUVToken = {
            (_: CTAP2.ClientPin.Method, _, _) throws(CTAP2.SessionError) -> CTAP2.Token in
            guard pinSet.value else {
                throw CTAP2.SessionError.ctapError(.pinNotSet, source: .here())
            }
            return CTAP2.Token(token: Data(repeating: 0, count: 32), protocolVersion: .v2)
        }
        webauthn.onMakeCredential = { _ in
            .mocked(.finished(.stub(credentialId: Data([0xAA]))))
        }

        let pinSetup = MockPINSetupBackend()
        pinSetup.onSetPIN = { _ in pinSet.value = true }

        // openNFC call sequence:
        //   1: ceremony body — succeed (yields .pinNotSet from the stream)
        //   2: applySetup — throw transient (createPIN form re-arms)
        //   3+: succeed (setPIN, then post-recovery ceremony)
        let mockTransport = MockTransportController(
            webauthn: webauthn,
            pinSetup: pinSetup,
            minPINLength: 4,
            transport: defaultMockTransport
        )
        mockTransport.onAcquire = { count in
            acquireAttempts.value = count
            if count == 2 {
                throw FidoUI.Error.webAuthn(.authenticatorNotAvailable(source: .here()))
            }
        }
        let fido = FidoUI(testTransportFactory: { _ in mockTransport })
        return await runMakeCredential(fido, options: regOptions(), serviceName: "example.com")
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
