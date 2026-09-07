// Copyright Yubico AB
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import Foundation
import Testing

@_spi(YubiInternal) @testable import YubiKit

/// SDK-surface ceremony tests for `WebAuthn.Client`, driven through
/// `MockCTAP2Backend`. These exercise the Swift client (status stream,
/// pre-supplied PIN, cancellation, and the credProtect/credProps extension
/// echoes) without touching a YubiKey — migrated from the integration
/// `WebAuthn.Ceremony.*` / `WebAuthn.CredProtect.*` / `WebAuthn.CredProps.*`
/// scenarios.
@Suite("WebAuthn Ceremony Tests")
struct CeremonyTests {

    private static let registrationOptions = WebAuthn.Registration.Options(
        challenge: Data(repeating: 0x01, count: 32),
        rp: .init(id: "example.com", name: "Example RP"),
        user: .init(id: Data(repeating: 0x02, count: 32), name: "user@example.com", displayName: "User"),
        residentKey: .discouraged
    )

    private static let authenticationOptions = WebAuthn.Authentication.Options(
        challenge: Data(repeating: 0x03, count: 32),
        rpId: "example.com"
    )

    // A PIN-only authenticator (clientPin set, no built-in UV). `.pin(_)`
    // authorization skips UV and goes straight to the PIN path.
    private static func pinBackend() -> MockCTAP2Backend {
        let mock = MockCTAP2Backend()
        mock.onGetInfo = { .stub(clientPin: true, pinUvAuthToken: true) }
        mock.onGetPinRetries = { .init(retries: 8, powerCycleState: false) }
        mock.onGetUVRetries = { 0 }
        mock.onGetPinUVToken = { _, _, _ throws(CTAP2.SessionError) in
            CTAP2.Token(token: Data(repeating: 0, count: 32), protocolVersion: .v2)
        }
        return mock
    }

    @Test("CTAP2 applies the requested timeout to both ceremonies", arguments: [true, false])
    func appliesTimeout(registration: Bool) async throws {
        let mock = Self.pinBackend()
        mock.onMakeCredential = { _ in
            CTAP2.StatusStream { continuation in
                Task {
                    try? await Task.sleep(for: .milliseconds(200))
                    continuation.finish()
                }
            }
        }
        mock.onGetAssertion = { _ in
            CTAP2.StatusStream { continuation in
                Task {
                    try? await Task.sleep(for: .milliseconds(200))
                    continuation.finish()
                }
            }
        }
        let client = try WebAuthn.Client.make(backend: mock)
        do {
            if registration {
                _ = try await client.makeCredential(
                    .init(
                        challenge: Self.registrationOptions.challenge,
                        rp: Self.registrationOptions.rp,
                        user: Self.registrationOptions.user,
                        residentKey: .discouraged,
                        timeout: .milliseconds(10)
                    ),
                    authorization: .pin("1234")
                ).value
            } else {
                _ = try await client.getAssertion(
                    .init(
                        challenge: Self.authenticationOptions.challenge,
                        rpId: Self.authenticationOptions.rpId,
                        timeout: .milliseconds(10)
                    ),
                    authorization: .pin("1234")
                ).value
            }
            Issue.record("Expected timeout")
        } catch {
            guard case WebAuthn.ClientError.timeout = error else {
                Issue.record("Expected timeout, got \(error)")
                return
            }
        }
    }

    // MARK: - Status Stream (PIN via closure)

    @Test("getAssertion status stream delivers waitingForUser and pulls the PIN via the closure exactly once")
    func testStatusStreamPullsPINOnce() async throws {
        let mock = Self.pinBackend()
        // The CTAP getAssertion command surfaces user presence then finishes.
        mock.onGetAssertion = { _ in
            waitingThenFinished(.stub(credentialId: Data([0xAA])))
        }

        let client = try WebAuthn.Client.make(backend: mock)

        let pinAsks = Box(0)
        let auth = WebAuthn.Authorization(
            providePIN: {
                pinAsks.value += 1
                return .pin("1234")
            },
            uv: .skipped
        )

        var sawWaitingForUser = false
        var sawUVWaiting = false
        var matches: [WebAuthn.Authentication.Response]?
        for try await status in await client.getAssertion(Self.authenticationOptions, authorization: auth) {
            switch status {
            case .processing:
                break
            case .waitingForUser:
                sawWaitingForUser = true
            case .waitingForUserVerification:
                sawUVWaiting = true
            case .finished(let result):
                matches = result
            }
        }

        #expect(pinAsks.value == 1, "PIN closure should have been invoked exactly once")
        #expect(sawWaitingForUser, "Stream should have delivered waitingForUser")
        #expect(!sawUVWaiting, "UV should be skipped under .pin authorization")
        let resolved = try #require(matches, "Stream should have delivered .finished with matches")
        #expect(!resolved.isEmpty)
        #expect((resolved.first?.signature.count ?? 0) > 0)
    }

    // MARK: - Pre-supplied PIN

    @Test("makeCredential consumes a pre-supplied PIN silently while still emitting waitingForUser")
    func testPrefetchedPINMakeCredential() async throws {
        let mock = Self.pinBackend()
        let pinAsks = Box(0)
        mock.onGetPinUVToken = { method, _, _ throws(CTAP2.SessionError) in
            if case .pin = method { pinAsks.value += 1 }
            return CTAP2.Token(token: Data(repeating: 0, count: 32), protocolVersion: .v2)
        }
        mock.onMakeCredential = { _ in
            waitingThenFinished(makeCredentialResponse(credentialId: Data([0xBB])))
        }

        let client = try WebAuthn.Client.make(backend: mock)

        var sawWaitingForUser = false
        var sawUVWaiting = false
        var finished = false
        for try await status in await client.makeCredential(Self.registrationOptions, authorization: .pin("1234")) {
            switch status {
            case .processing:
                break
            case .waitingForUser:
                sawWaitingForUser = true
            case .waitingForUserVerification:
                sawUVWaiting = true
            case .finished:
                finished = true
            }
        }

        // `.pin(_)` supplies the PIN directly — the SDK consumes it without a
        // second prompt, but still surfaces user presence.
        #expect(pinAsks.value == 1, "The pre-supplied PIN should be used once")
        #expect(sawWaitingForUser, "Stream should still deliver waitingForUser")
        #expect(!sawUVWaiting, "UV should be skipped under .pin authorization")
        #expect(finished, "Stream should reach .finished")
    }

    @Test("getAssertion consumes a pre-supplied PIN silently")
    func testPrefetchedPINGetAssertion() async throws {
        let mock = Self.pinBackend()
        mock.onGetAssertion = { _ in
            waitingThenFinished(.stub(credentialId: Data([0xCC])))
        }

        let client = try WebAuthn.Client.make(backend: mock)

        var matches: [WebAuthn.Authentication.Response]?
        for try await status in await client.getAssertion(Self.authenticationOptions, authorization: .pin("1234")) {
            if case .finished(let result) = status { matches = result }
        }

        let resolved = try #require(matches, "Stream should have delivered .finished with matches")
        #expect(!resolved.isEmpty)
        #expect((resolved.first?.signature.count ?? 0) > 0)
    }

    // MARK: - Cancellation

    @Test("makeCredential can be cancelled from the status stream")
    func testCancelMakeCredential() async throws {
        let mock = Self.pinBackend()
        // Cancelling on waitingForUser aborts the in-flight CTAP command, which
        // surfaces a keepaliveCancel — mapped to ClientError.cancelled.
        mock.onMakeCredential = { _ in
            CTAP2.StatusStream { continuation in
                Task {
                    continuation.yield(
                        .waitingForUser(cancel: {
                            continuation.yield(error: .ctapError(.keepaliveCancel, source: .here()))
                        })
                    )
                }
            }
        }

        let client = try WebAuthn.Client.make(backend: mock)

        var caught: WebAuthn.ClientError?
        var reachedFinished = false
        do throws(WebAuthn.ClientError) {
            for try await status in await client.makeCredential(Self.registrationOptions, authorization: .pin("1234")) {
                switch status {
                case .waitingForUser(let cancel):
                    await cancel()
                case .finished:
                    reachedFinished = true
                default:
                    break
                }
            }
        } catch {
            caught = error
        }

        #expect(!reachedFinished, "makeCredential should have been cancelled before finishing")
        guard case .cancelled = caught else {
            Issue.record("Expected cancelled, got \(String(describing: caught))")
            return
        }
    }

    // MARK: - credProtect echo

    // The client reads the applied credProtect policy from the authenticator-data
    // extensions of the makeCredential response (`parseRegistrationOutputs`). Drive
    // that parse directly — the credProtect *input* path needs a live session for
    // `makeCredProtect`, which the mock backend can't provide.

    @Test("credProtect echoes the applied protection level for each policy")
    func testCredProtectAllLevels() async throws {
        let mock = MockCTAP2Backend()

        for policy in [
            WebAuthn.Extension.CredProtect.Policy.userVerificationOptional,
            .userVerificationOptionalWithCredentialIDList,
            .userVerificationRequired,
        ] {
            let outputs = try await mock.parseRegistrationOutputs(
                from: makeCredentialResponse(credentialId: Data([0xDD]), credProtectLevel: policy.rawValue),
                prf: nil,
                previewSign: nil,
                largeBlobRequested: false,
                credPropsRk: nil,
                allowedExtensions: [.credProtect]
            )
            #expect(outputs.credProtect?.policy == policy, "level \(policy) should be echoed")
        }
    }

    @Test("credProtect is not echoed when the authenticator omits it from authenticator data")
    func testCredProtectNotEchoedWhenAbsent() async throws {
        let mock = MockCTAP2Backend()
        let outputs = try await mock.parseRegistrationOutputs(
            from: makeCredentialResponse(credentialId: Data([0xDD]), credProtectLevel: nil),
            prf: nil,
            previewSign: nil,
            largeBlobRequested: false,
            credPropsRk: nil,
            allowedExtensions: [.credProtect]
        )
        #expect(outputs.credProtect == nil, "no credProtect should be returned when absent")
    }

    // MARK: - credProps rk

    @Test("credProps reports rk=true for a discoverable credential")
    func testCredPropsDiscoverable() async throws {
        let rk = try await credPropsRk(residentKey: .required, credProps: true)
        #expect(rk == true)
    }

    @Test("credProps reports rk=false for a non-discoverable credential")
    func testCredPropsNonDiscoverable() async throws {
        let rk = try await credPropsRk(residentKey: .discouraged, credProps: true)
        #expect(rk == false)
    }

    @Test("credProps is nil when not requested")
    func testCredPropsNotRequested() async throws {
        let mock = Self.pinBackend()
        mock.onMakeCredential = { _ in .mocked(.finished(makeCredentialResponse(credentialId: Data([0xEE])))) }
        let client = try makeCredPropsClient(mock)

        let options = WebAuthn.Registration.Options(
            challenge: Data(repeating: 0x01, count: 32),
            rp: .init(id: "example.com", name: "CredProps Test"),
            user: .init(id: Data(repeating: 0x02, count: 32), name: "cp@example.com", displayName: "CP"),
            residentKey: .required
        )

        let response = try await client.makeCredential(options, authorization: .pin("1234")).value
        #expect(response.clientExtensionResults.credProps == nil)
    }

    private func credPropsRk(
        residentKey: WebAuthn.ResidentKeyPreference,
        credProps: Bool
    ) async throws -> Bool? {
        let mock = Self.pinBackend()
        // rk-capable authenticator so residentKey: .required resolves to rk=true.
        mock.onMakeCredential = { _ in .mocked(.finished(makeCredentialResponse(credentialId: Data([0xEE])))) }
        let client = try makeCredPropsClient(mock)

        let options = WebAuthn.Registration.Options(
            challenge: Data(repeating: 0x01, count: 32),
            rp: .init(id: "example.com", name: "CredProps Test"),
            user: .init(id: Data(repeating: 0x02, count: 32), name: "cp@example.com", displayName: "CP"),
            residentKey: residentKey,
            extensions: .init(credProps: credProps)
        )

        let response = try await client.makeCredential(options, authorization: .pin("1234")).value
        #expect(response.clientExtensionResults.credProps != nil, "credProps should be present when requested")
        return response.clientExtensionResults.credProps?.rk
    }

    // MARK: - clientDataJSON key ordering

    @Test("clientDataJSON serializes keys in spec order: type, challenge, origin, crossOrigin")
    func testClientDataJSONKeyOrdering() throws {
        let clientData = WebAuthn.ClientData.webauthn(
            type: "webauthn.create",
            challenge: Data(repeating: 0x01, count: 32),
            origin: try WebAuthn.Origin("https://example.com"),
            rpId: "example.com",
            crossOrigin: false
        )
        let json = try #require(clientData.clientDataJSON)
        let string = try #require(String(data: json, encoding: .utf8))

        #expect(string.contains("webauthn.create"))
        #expect(string.contains("example.com"))

        let typeIndex = try #require(string.range(of: "\"type\"")?.lowerBound)
        let challengeIndex = try #require(string.range(of: "\"challenge\"")?.lowerBound)
        let originIndex = try #require(string.range(of: "\"origin\"")?.lowerBound)
        let crossOriginIndex = try #require(string.range(of: "\"crossOrigin\"")?.lowerBound)
        #expect(typeIndex < challengeIndex, "type should come before challenge")
        #expect(challengeIndex < originIndex, "challenge should come before origin")
        #expect(originIndex < crossOriginIndex, "origin should come before crossOrigin")
    }

    // MARK: - Clients with specific allowed extensions

    private func makeCredPropsClient(_ backend: MockCTAP2Backend) throws -> WebAuthn.Client {
        WebAuthn.Client(
            backend: backend,
            origin: try WebAuthn.Origin("https://example.com"),
            allowedExtensions: [.credProps],
            isPublicSuffix: { _ in false }
        )
    }
}

// MARK: - StatusStream helper

/// Yields `.waitingForUser` (no-op cancel) and then a finished response —
/// mirrors a CTAP command that reports user presence before completing.
private func waitingThenFinished<R: Sendable>(_ response: R) -> CTAP2.StatusStream<R> {
    CTAP2.StatusStream { continuation in
        continuation.yield(.waitingForUser(cancel: {}))
        continuation.yield(.finished(response))
    }
}

// MARK: - MakeCredential.Response fixture

/// Builds a minimal but valid `CTAP2.MakeCredential.Response` with attested
/// credential data (ES256 P-256), optionally carrying a credProtect output in
/// the authenticator-data extensions block.
private func makeCredentialResponse(
    credentialId: Data,
    credProtectLevel: Int? = nil
) -> CTAP2.MakeCredential.Response {
    var authData = Data()
    authData.append(Data(repeating: 0xAB, count: 32))  // rpIdHash
    // flags: UP + AT (+ ED when extensions are present)
    let edFlag: UInt8 = credProtectLevel == nil ? 0 : 0x80
    authData.append(0x41 | edFlag)
    authData.append(contentsOf: [0x00, 0x00, 0x00, 0x01])  // signCount = 1

    // Attested credential data
    authData.append(Data(repeating: 0, count: 16))  // aaguid
    let len = credentialId.count
    authData.append(contentsOf: [UInt8(len >> 8), UInt8(len & 0xFF)])  // credentialId length
    authData.append(credentialId)

    // Minimal ES256 P-256 COSE key
    let coseKey: [CBOR.Value: CBOR.Value] = [
        .int(1): .int(2),  // kty: EC2
        .int(3): .int(-7),  // alg: ES256
        .int(-1): .int(1),  // crv: P-256
        .int(-2): .byteString(Data(repeating: 0x01, count: 32)),  // x
        .int(-3): .byteString(Data(repeating: 0x02, count: 32)),  // y
    ]
    authData.append(CBOR.Value.map(coseKey).encode())

    // Optional credProtect extension output (signed authenticator-data extensions).
    if let credProtectLevel {
        let extensions: [CBOR.Value: CBOR.Value] = [
            .textString("credProtect"): .int(credProtectLevel)
        ]
        authData.append(CBOR.Value.map(extensions).encode())
    }

    let response: [CBOR.Value: CBOR.Value] = [
        .int(0x01): .textString("none"),
        .int(0x02): .byteString(authData),
        .int(0x03): .map([:]),
    ]
    let cbor: CBOR.Value = .map(response)
    guard let parsed = CTAP2.MakeCredential.Response(cbor: cbor) else {
        preconditionFailure("makeCredentialResponse fixture built CBOR that MakeCredential.Response rejected")
    }
    return parsed
}
