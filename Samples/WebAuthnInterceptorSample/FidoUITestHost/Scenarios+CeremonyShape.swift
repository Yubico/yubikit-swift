import Foundation

@testable import FidoUI
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

    /// Full "signed up, now sign in" journey: register a new passkey,
    /// dismiss success, then authenticate against the same rpId with two
    /// matching credentials (the new one plus a stale discoverable). Picker
    /// appears; user picks the first credential (the one they just
    /// registered); success.
    static func flowRegisterThenAuth() async -> ScenarioStatus.Outcome {
        let webauthn = MockWebAuthnBackend()
        webauthn.onGetInfo = { .stub(clientPin: false, pinUvAuthToken: false) }
        webauthn.onMakeCredential = { _ in
            .mocked(.finished(.stub(credentialId: Data([0xAA]))))
        }

        let credA = Data([0xAA])
        let userA = WebAuthn.User.stub(
            id: Data([1]),
            name: "user@example.com",
            displayName: "User"
        )
        // Stale discoverables on the same rpId — `userA` is the just-registered
        // one (test taps row 0); the rest exercise the scroll/overflow path.
        let staleUsers: [(Data, WebAuthn.User)] = [
            (Data([0xBB]), .stub(id: Data([2]), name: "old@example.com", displayName: "Old Account")),
            (Data([0xCC]), .stub(id: Data([3]), name: "alice@example.com", displayName: "Alice")),
            (Data([0xDD]), .stub(id: Data([4]), name: "bob@example.com", displayName: "Bob")),
            (Data([0xEE]), .stub(id: Data([5]), name: "carol@example.com", displayName: "Carol")),
        ]
        let total = 1 + staleUsers.count
        let nextIndex = Box(0)
        webauthn.onGetAssertion = { _ in
            .mocked(.finished(.stub(credentialId: credA, user: userA, numberOfCredentials: total)))
        }
        webauthn.onGetNextAssertion = {
            let (id, user) = staleUsers[nextIndex.value]
            nextIndex.value += 1
            return .mocked(.finished(.stub(credentialId: id, user: user)), touchDelay: .zero)
        }

        let fido = makeMockedFidoUI(webauthn: webauthn)

        // Bail if registration fails — there's no passkey to authenticate against.
        // Use a Registration.Options with `user: userA` so the registered user
        // matches the discoverable returned by getAssertion below.
        let registration = WebAuthn.Registration.Options(
            challenge: Data(repeating: 0x02, count: 32),
            rp: .init(id: "example.com", name: "example.com"),
            user: userA,
            userVerification: .discouraged
        )
        let regOutcome = await runMakeCredential(fido, options: registration, serviceName: "example.com")
        guard case .completed = regOutcome else { return regOutcome }

        // Visible gap between ceremonies so the alert window clearly closes
        // before the sign-in flow re-opens it — otherwise the two ceremonies
        // blur into one continuous alert.
        try? await Task.sleep(for: .seconds(1.2))

        return await runGetAssertion(fido, options: authOptions(uv: .discouraged), serviceName: "example.com")
    }

    /// First makeCredential stream errors with a transport-level
    /// `connectionError`, which the SDK maps to
    /// `WebAuthn.ClientError.authenticatorNotAvailable`. `runCeremony` catches
    /// it, switches `phase = .reconnect`, shows the waiting bridge panel,
    /// re-acquires a session, and the second attempt succeeds.
    static func flowConnectionDropMidCeremony() async -> ScenarioStatus.Outcome {
        let attempts = Box(0)
        let mock = MockWebAuthnBackend()
        mock.onGetInfo = { .stub(clientPin: false, pinUvAuthToken: false) }
        mock.onMakeCredential = { _ in
            attempts.value += 1
            if attempts.value == 1 {
                return .mocked(
                    error: .connectionError(.connectionLost, source: .here())
                )
            }
            return .mocked(.finished(.stub(credentialId: Data([0xAA]))))
        }

        return await runRegistration(webauthn: mock, uv: .discouraged)
    }
}
