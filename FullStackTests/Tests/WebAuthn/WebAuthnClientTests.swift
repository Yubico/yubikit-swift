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

@testable import YubiKit

// MARK: - Test Configuration

private let testOrigin = try! WebAuthn.Origin("https://example.com")
private let testRpId = "example.com"
private let testRpName = "Example RP"

// MARK: - Tests

@Suite("WebAuthn Client Full Stack Tests", .serialized)
struct WebAuthnClientFullStackTests {

    // MARK: - Setup

    @Test(
        "Reset - Factory Reset",
        .disabled("Destructive - clears all credentials and PIN")
    )
    func testReset() async throws {
        try await CTAP2FullStackTests().testReset()
    }

    @Test("Setup - Ensure PIN is Set")
    func testPinSetup() async throws {
        try await CTAP2FullStackTests().testClientPinSetup(pinProtocol: .v2)
    }

    // MARK: - Core Flow

    @Test("Make Credential and Get Assertion")
    func testMakeCredentialGetAssertion() async throws {
        try await withReconnectableWebAuthnClient { client, _, reconnect in
            var client = client
            let userId = randomBytes(count: 32)

            let createOptions = WebAuthn.Registration.Options(
                challenge: randomBytes(count: 32),
                rp: .init(id: testRpId, name: testRpName),
                user: .init(id: userId, name: "test@example.com", displayName: "Test User"),
                residentKey: .required
            )

            print("Making credential...")
            let createResponse = try await client.makeCredential(createOptions, authorization: .pin(defaultTestPin))
                .value

            #expect(createResponse.credentialId.count > 0)
            #expect(createResponse.authenticatorData.attestedCredentialData != nil)
            print("Credential created")

            client = try await reconnect().client

            let requestOptions = WebAuthn.Authentication.Options(
                challenge: randomBytes(count: 32),
                rpId: testRpId
            )

            print("Getting assertion...")
            let matches = try await client.getAssertion(requestOptions, authorization: .pin(defaultTestPin)).value
            let assertResponse = matches[0]

            #expect(assertResponse.rawAuthenticatorData.count > 0)
            #expect(assertResponse.signature.count > 0)
            #expect(assertResponse.user?.id == userId)
            print("Assertion successful")
        }
    }

    // MARK: - Allow Credentials

    @Test("Get Assertion with Allow Credentials")
    func testGetAssertionWithAllowCredentials() async throws {
        try await withReconnectableWebAuthnClient { client, _, reconnect in
            var client = client

            let createOptions = WebAuthn.Registration.Options(
                challenge: randomBytes(count: 32),
                rp: .init(id: testRpId, name: testRpName),
                user: .init(
                    id: randomBytes(count: 32),
                    name: "allow@example.com",
                    displayName: "Allow User"
                ),
                residentKey: .required
            )

            print("Making credential...")
            let createResponse = try await client.makeCredential(createOptions, authorization: .pin(defaultTestPin))
                .value

            client = try await reconnect().client

            let requestOptions = WebAuthn.Authentication.Options(
                challenge: randomBytes(count: 32),
                rpId: testRpId,
                allowCredentials: [.init(id: createResponse.credentialId)]
            )

            print("Getting assertion with allow credentials...")
            let matches = try await client.getAssertion(requestOptions, authorization: .pin(defaultTestPin)).value
            let assertResponse = matches[0]

            #expect(assertResponse.credentialId == createResponse.credentialId)
            #expect(assertResponse.signature.count > 0)
            print("Assertion successful")
        }
    }

    @Test("Get Assertions - Allow List No Match")
    func testGetAssertionsAllowListNoMatch() async throws {
        try await withWebAuthnClient { client in
            let requestOptions = WebAuthn.Authentication.Options(
                challenge: randomBytes(count: 32),
                rpId: testRpId,
                allowCredentials: [.init(id: randomBytes(count: 32))]
            )

            print("Getting assertion with non-existent credential...")
            do {
                _ = try await client.getAssertion(requestOptions, authorization: .pin(defaultTestPin)).value
                Issue.record("Should have thrown noCredentials error")
            } catch let error as WebAuthn.ClientError {
                guard case .noCredentials = error else {
                    Issue.record("Expected noCredentials error, got: \(error)")
                    return
                }
                print("Correctly received noCredentials error")
            }
        }
    }

    // MARK: - Exclude Credentials

    @Test("Make Credential with Exclude Credentials")
    func testMakeCredentialWithExcludeCredentials() async throws {
        try await withReconnectableWebAuthnClient { client, _, reconnect in
            var client = client

            let createOptions = WebAuthn.Registration.Options(
                challenge: randomBytes(count: 32),
                rp: .init(id: testRpId, name: testRpName),
                user: .init(
                    id: randomBytes(count: 32),
                    name: "exclude@example.com",
                    displayName: "Exclude User"
                ),
                residentKey: .required
            )

            print("Making initial credential...")
            let createResponse = try await client.makeCredential(createOptions, authorization: .pin(defaultTestPin))
                .value

            client = try await reconnect().client

            let excludeOptions = WebAuthn.Registration.Options(
                challenge: randomBytes(count: 32),
                rp: .init(id: testRpId, name: testRpName),
                user: .init(
                    id: randomBytes(count: 32),
                    name: "exclude2@example.com",
                    displayName: "Exclude User 2"
                ),
                excludeCredentials: [.init(id: createResponse.credentialId)],
                residentKey: .required
            )

            print("Making credential with exclude list...")
            do {
                _ = try await client.makeCredential(excludeOptions, authorization: .pin(defaultTestPin)).value
                Issue.record("Should have thrown credentialExcluded error")
            } catch let error as WebAuthn.ClientError {
                guard case .credentialExcluded = error else {
                    Issue.record("Expected credentialExcluded error, got: \(error)")
                    return
                }
                print("Correctly received credentialExcluded error")
            }
        }
    }

    // MARK: - Multiple Credentials

    @Test("Get Assertions - Multiple Discoverable Credentials with Selection")
    func testGetAssertionsMultipleCredentials() async throws {
        try await withReconnectableWebAuthnClient { client, _, reconnect in
            var client = client
            let credentialCount = 3
            var userIds: [Data] = []

            for i in 0..<credentialCount {
                let userId = randomBytes(count: 32)
                userIds.append(userId)

                let createOptions = WebAuthn.Registration.Options(
                    challenge: randomBytes(count: 32),
                    rp: .init(id: testRpId, name: testRpName),
                    user: .init(
                        id: userId,
                        name: "user\(i)@example.com",
                        displayName: "User \(i)"
                    ),
                    residentKey: .required
                )

                print("Making credential \(i + 1)/\(credentialCount)...")
                _ = try await client.makeCredential(createOptions, authorization: .pin(defaultTestPin)).value
                client = try await reconnect().client
            }

            let requestOptions = WebAuthn.Authentication.Options(
                challenge: randomBytes(count: 32),
                rpId: testRpId
            )

            print("Getting matched credentials for selection...")
            let matches = try await client.getAssertion(requestOptions, authorization: .pin(defaultTestPin)).value

            #expect(matches.count >= credentialCount, "Should have at least \(credentialCount) matched credentials")
            print("Found \(matches.count) matched credentials")

            // Verify each match has credential info for selection UI
            for match in matches {
                #expect(match.credentialId.count > 0, "Credential ID should be present")
                #expect(match.user != nil, "User info should be present for discoverable credentials")
            }

            // Select the second credential (not first) to verify selection works
            let chosenIndex = min(1, matches.count - 1)
            let chosen = matches[chosenIndex]
            print("Selecting credential at index \(chosenIndex): \(chosen.user?.name ?? "unknown")")

            #expect(chosen.signature.count > 0)
            #expect(chosen.rawAuthenticatorData.count > 0)
            print("Selection completed successfully")
        }
    }

    // MARK: - RP ID Validation

    @Test("Make Credential - RP ID Mismatch")
    func testMakeCredentialRpIdMismatch() async throws {
        try await withCTAP2Session { session in
            let client = WebAuthn.Client(
                session: session,
                origin: try WebAuthn.Origin("https://example.com"),

                isPublicSuffix: { _ in false }
            )

            let options = WebAuthn.Registration.Options(
                challenge: randomBytes(count: 32),
                rp: .init(id: "other.com", name: "Other RP"),
                user: .init(
                    id: randomBytes(count: 32),
                    name: "test@other.com",
                    displayName: "Test User"
                )
            )

            print("Attempting credential with mismatched RP ID...")
            do {
                _ = try await client.makeCredential(options, authorization: .pin(defaultTestPin)).value
                Issue.record("Should have thrown invalidRequest error")
            } catch let error as WebAuthn.ClientError {
                guard case .invalidRequest(let message, _) = error else {
                    Issue.record("Expected invalidRequest error, got: \(error)")
                    return
                }
                #expect(message.contains("other.com"))
                print("Correctly rejected mismatched RP ID: \(message)")
            }
        }
    }

    @Test("Make Credential - Public Suffix RP ID Rejected")
    func testMakeCredentialPublicSuffixRejected() async throws {
        try await withCTAP2Session { session in
            let client = WebAuthn.Client(
                session: session,
                origin: try WebAuthn.Origin("https://mysite.co.uk"),

                isPublicSuffix: { $0 == "co.uk" }
            )

            let options = WebAuthn.Registration.Options(
                challenge: randomBytes(count: 32),
                rp: .init(id: "co.uk", name: "Bad RP"),
                user: .init(
                    id: randomBytes(count: 32),
                    name: "test@mysite.co.uk",
                    displayName: "Test User"
                )
            )

            print("Attempting credential with public suffix RP ID...")
            do {
                _ = try await client.makeCredential(options, authorization: .pin(defaultTestPin)).value
                Issue.record("Should have thrown invalidRequest error")
            } catch let error as WebAuthn.ClientError {
                guard case .invalidRequest(let message, _) = error else {
                    Issue.record("Expected invalidRequest error, got: \(error)")
                    return
                }
                #expect(message.contains("public suffix"))
                print("Correctly rejected public suffix RP ID: \(message)")
            }
        }
    }

    // MARK: - PIN Errors

    @Test("Make Credential - Wrong PIN Returns Error")
    func testMakeCredentialWrongPinError() async throws {
        try await withCTAP2Session { session in
            let client = WebAuthn.Client(
                session: session,
                origin: testOrigin,
                isPublicSuffix: { _ in false }
            )

            let options = WebAuthn.Registration.Options(
                challenge: randomBytes(count: 32),
                rp: .init(id: testRpId, name: testRpName),
                user: .init(
                    id: randomBytes(count: 32),
                    name: "wrongpin@example.com",
                    displayName: "Wrong PIN User"
                ),
                residentKey: .discouraged
            )

            print("Attempting credential with wrong PIN...")
            do {
                _ = try await client.makeCredential(options, authorization: .pin("wrongpin123")).value
                Issue.record("Should have thrown pinRejected error")
            } catch let error as WebAuthn.ClientError {
                guard case .pinRejected(let retries, _) = error else {
                    Issue.record("Expected pinRejected error, got: \(error)")
                    return
                }
                #expect(retries < 8, "Retry counter should have decremented")
                print("Correctly received pinRejected with \(retries) retries remaining")
            }
        }
    }

    // MARK: - ClientData

    @Test("ClientData JSON Format")
    func testClientDataJsonFormat() async throws {
        try await withWebAuthnClient { client in
            let challenge = randomBytes(count: 32)

            let options = WebAuthn.Registration.Options(
                challenge: challenge,
                rp: .init(id: testRpId, name: testRpName),
                user: .init(
                    id: randomBytes(count: 32),
                    name: "clientdata@example.com",
                    displayName: "ClientData Test"
                ),
                residentKey: .required
            )

            let clientData = WebAuthn.ClientData.webauthn(
                type: "webauthn.create",
                challenge: challenge,
                origin: testOrigin,
                rpId: testRpId,
                crossOrigin: false
            )

            print("Making credential to verify clientDataJSON...")
            let response = try await client.makeCredential(
                options,
                clientData: clientData,
                authorization: .pin(defaultTestPin)
            ).value

            guard let clientDataJSON = response.clientDataJSON else {
                Issue.record("clientDataJSON should not be nil for client-initiated flows")
                return
            }
            #expect(clientDataJSON.count > 0, "clientDataJSON should not be empty")

            let jsonString = String(data: clientDataJSON, encoding: .utf8)!
            print("clientDataJSON: \(jsonString)")

            #expect(jsonString.contains("\"type\""))
            #expect(jsonString.contains("\"challenge\""))
            #expect(jsonString.contains("\"origin\""))
            #expect(jsonString.contains("\"crossOrigin\""))
            #expect(jsonString.contains("webauthn.create"))
            #expect(jsonString.contains("example.com"))

            // Verify key ordering per WebAuthn spec: type, challenge, origin, crossOrigin
            let typeIndex = jsonString.range(of: "\"type\"")!.lowerBound
            let challengeIndex = jsonString.range(of: "\"challenge\"")!.lowerBound
            let originIndex = jsonString.range(of: "\"origin\"")!.lowerBound
            let crossOriginIndex = jsonString.range(of: "\"crossOrigin\"")!.lowerBound

            #expect(typeIndex < challengeIndex, "type should come before challenge")
            #expect(challengeIndex < originIndex, "challenge should come before origin")
            #expect(originIndex < crossOriginIndex, "origin should come before crossOrigin")

            print("clientDataJSON format verified")
        }
    }

    // MARK: - Status Stream

    @Test("Get Assertions - Status Stream delivers user-presence events; closures supply PIN")
    func testGetAssertionStatusStream() async throws {
        try await withReconnectableWebAuthnClient { client, _, reconnect in
            var client = client

            let createOptions = WebAuthn.Registration.Options(
                challenge: randomBytes(count: 32),
                rp: .init(id: testRpId, name: testRpName),
                user: .init(
                    id: randomBytes(count: 32),
                    name: "stream@example.com",
                    displayName: "Stream User"
                ),
                residentKey: .required
            )

            print("Making credential...")
            _ = try await client.makeCredential(createOptions, authorization: .pin(defaultTestPin)).value
            client = try await reconnect().client

            let requestOptions = WebAuthn.Authentication.Options(
                challenge: randomBytes(count: 32),
                rpId: testRpId
            )

            print("Iterating getAssertions status stream...")
            let pinAsks = Box(0)
            var sawWaitingForUser = false
            var matches: [WebAuthn.Authentication.Response]?

            let stream = await client.getAssertion(
                requestOptions,
                authorization: .init(
                    providePIN: {
                        print("PIN requested via closure - submitting")
                        pinAsks.value += 1
                        return .pin(defaultTestPin)
                    },
                    uv: .skipped
                )
            )
            for try await status in stream {
                switch status {
                case .processing:
                    print("Processing...")
                case .waitingForUser:
                    print("Waiting for user...")
                    sawWaitingForUser = true
                case .waitingForUserVerification:
                    Issue.record("UV should be skipped under .pin authorization")
                case .finished(let result):
                    matches = result
                }
            }

            #expect(pinAsks.value == 1, "PIN closure should have been invoked exactly once")
            #expect(sawWaitingForUser, "Stream should have delivered waitingForUser")
            guard let matches else {
                Issue.record("Stream should have delivered .finished with matches")
                return
            }
            #expect(!matches.isEmpty, "Should have at least one matched credential")

            let response = matches[0]
            #expect(response.signature.count > 0)
            print("Status stream assertion completed successfully")
        }
    }

    // MARK: - Discoverable - No Credentials

    @Test("Get Assertions - Discoverable with no credentials for RP")
    func testGetAssertionsDiscoverableNoCredentials() async throws {
        let unusedRpId = "no-creds-\(UUID().uuidString.prefix(8)).example.com"
        let unusedOrigin = try WebAuthn.Origin("https://\(unusedRpId)")

        try await withCTAP2Session { session in
            let client = WebAuthn.Client(
                session: session,
                origin: unusedOrigin,
                isPublicSuffix: { _ in false }
            )

            let requestOptions = WebAuthn.Authentication.Options(
                challenge: randomBytes(count: 32),
                rpId: unusedRpId
            )

            print("Getting discoverable assertions for RP with no credentials...")
            do {
                _ = try await client.getAssertion(requestOptions, authorization: .pin(defaultTestPin)).value
                Issue.record("Should have thrown noCredentials error")
            } catch let error as WebAuthn.ClientError {
                guard case .noCredentials = error else {
                    Issue.record("Expected noCredentials error, got: \(error)")
                    return
                }
                print("Correctly received noCredentials error for discoverable path")
            }
        }
    }

    // MARK: - Pre-supplied PIN

    @Test("Make Credential - Pre-supplied PIN consumed silently")
    func testMakeCredentialPrefetchedPIN() async throws {
        try await withWebAuthnClient { client in
            let options = WebAuthn.Registration.Options(
                challenge: randomBytes(count: 32),
                rp: .init(id: testRpId, name: testRpName),
                user: .init(
                    id: randomBytes(count: 32),
                    name: "prefetched-pin@example.com",
                    displayName: "Prefetched PIN User"
                ),
                residentKey: .discouraged
            )

            print("Iterating makeCredential stream with pre-supplied PIN...")
            var sawWaitingForUser = false
            var finished = false

            for try await status in await client.makeCredential(
                options,
                authorization: .pin(defaultTestPin)
            ) {
                switch status {
                case .processing:
                    break
                case .waitingForUser:
                    sawWaitingForUser = true
                case .waitingForUserVerification:
                    Issue.record("UV should be skipped under .pin authorization")
                case .finished:
                    finished = true
                }
            }

            #expect(sawWaitingForUser, "Stream should still deliver waitingForUser")
            #expect(finished, "Stream should reach .finished")
        }
    }

    @Test("Get Assertion - Pre-supplied PIN consumed silently")
    func testGetAssertionPrefetchedPIN() async throws {
        try await withReconnectableWebAuthnClient { client, _, reconnect in
            var client = client

            let createOptions = WebAuthn.Registration.Options(
                challenge: randomBytes(count: 32),
                rp: .init(id: testRpId, name: testRpName),
                user: .init(
                    id: randomBytes(count: 32),
                    name: "prefetched-ga@example.com",
                    displayName: "Prefetched GA User"
                ),
                residentKey: .required
            )

            _ = try await client.makeCredential(createOptions, authorization: .pin(defaultTestPin)).value
            client = try await reconnect().client

            let requestOptions = WebAuthn.Authentication.Options(
                challenge: randomBytes(count: 32),
                rpId: testRpId
            )

            print("Iterating getAssertion stream with pre-supplied PIN...")
            var matches: [WebAuthn.Authentication.Response]?

            for try await status in await client.getAssertion(
                requestOptions,
                authorization: .pin(defaultTestPin)
            ) {
                if case .finished(let result) = status { matches = result }
            }

            guard let matches else {
                Issue.record("Stream should have delivered .finished with matches")
                return
            }
            #expect(!matches.isEmpty)
            let response = matches[0]
            #expect(response.signature.count > 0)
        }
    }

    // MARK: - Cancellation

    @Test("Cancel Make Credential via Status Stream")
    func testCancelMakeCredentialViaStatusStream() async throws {
        try await withWebAuthnClient { client in
            let options = WebAuthn.Registration.Options(
                challenge: randomBytes(count: 32),
                rp: .init(id: testRpId, name: testRpName),
                user: .init(
                    id: randomBytes(count: 32),
                    name: "cancel@example.com",
                    displayName: "Cancel User"
                ),
                residentKey: .discouraged
            )

            print("Starting credential creation, will cancel on waitingForUser...")

            do {
                let stream = await client.makeCredential(options, authorization: .pin(defaultTestPin))
                for try await status in stream {
                    switch status {
                    case .processing:
                        print("Processing...")
                    case .waitingForUser(let cancel):
                        print("Waiting for user - cancelling now!")
                        await cancel()
                    case .waitingForUserVerification:
                        Issue.record("UV should be skipped under .pin authorization")
                    case .finished:
                        Issue.record("makeCredential should have been cancelled")
                    }
                }
                Issue.record("makeCredential should have thrown cancellation error")
            } catch let error as WebAuthn.ClientError {
                guard case .cancelled = error else {
                    Issue.record("Expected cancelled error, got: \(error)")
                    return
                }
                print("Cancellation successful")
            }
        }
    }
}

// MARK: - Helpers

func randomBytes(count: Int) -> Data {
    var bytes = [UInt8](repeating: 0, count: count)
    _ = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
    return Data(bytes)
}

private func withWebAuthnClient<T>(
    _ body: (WebAuthn.Client) async throws -> T
) async throws -> T {
    try await withCTAP2Session { session in
        let client = WebAuthn.Client(
            session: session,
            origin: testOrigin,
            isPublicSuffix: { _ in false }
        )
        return try await body(client)
    }
}

func withReconnectableWebAuthnClient<T>(
    _ body: (
        _ client: WebAuthn.Client,
        _ session: CTAP2.Session,
        _ reconnect: () async throws -> (client: WebAuthn.Client, session: CTAP2.Session)
    ) async throws -> T
) async throws -> T {
    try await withReconnectableCTAP2Session { session, reconnectSession in
        let client = WebAuthn.Client(
            session: session,
            origin: testOrigin,
            isPublicSuffix: { _ in false }
        )

        let reconnect: () async throws -> (client: WebAuthn.Client, session: CTAP2.Session) = {
            let newSession = try await reconnectSession()
            let newClient = WebAuthn.Client(
                session: newSession,
                origin: testOrigin,
                isPublicSuffix: { _ in false }
            )
            return (newClient, newSession)
        }

        return try await body(client, session, reconnect)
    }
}
