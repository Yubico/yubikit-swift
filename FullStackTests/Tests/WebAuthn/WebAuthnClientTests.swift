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
        try await withReconnectableWebAuthnClient { client, reconnect in
            var client = client
            let userId = randomBytes(count: 32)

            let createOptions = WebAuthn.Registration.Options(
                challenge: randomBytes(count: 32),
                rp: .init(id: testRpId, name: testRpName),
                user: .init(id: userId, name: "test@example.com", displayName: "Test User"),
                residentKey: .required
            )

            print("Making credential...")
            let createResponse = try await client.makeCredential(createOptions).value

            #expect(createResponse.credentialId.count > 0)
            #expect(createResponse.authenticatorData.attestedCredentialData != nil)
            print("Credential created")

            client = try await reconnect()

            let requestOptions = WebAuthn.Authentication.Options(
                challenge: randomBytes(count: 32),
                rpId: testRpId
            )

            print("Getting assertion...")
            let assertResponse = try await client.getAssertion(requestOptions).value

            #expect(assertResponse.rawAuthenticatorData.count > 0)
            #expect(assertResponse.signature.count > 0)
            #expect(assertResponse.user?.id == userId)
            print("Assertion successful")
        }
    }

    // MARK: - Allow Credentials

    @Test("Get Assertion with Allow Credentials")
    func testGetAssertionWithAllowCredentials() async throws {
        try await withReconnectableWebAuthnClient { client, reconnect in
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
            let createResponse = try await client.makeCredential(createOptions).value

            client = try await reconnect()

            let requestOptions = WebAuthn.Authentication.Options(
                challenge: randomBytes(count: 32),
                rpId: testRpId,
                allowCredentials: [.init(id: createResponse.credentialId)]
            )

            print("Getting assertion with allow credentials...")
            let assertResponse = try await client.getAssertion(requestOptions).value

            #expect(assertResponse.credentialId == createResponse.credentialId)
            #expect(assertResponse.signature.count > 0)
            print("Assertion successful")
        }
    }

    @Test("Get Assertion - No Matching Credentials")
    func testGetAssertionNoCredentials() async throws {
        try await withWebAuthnClient { client in
            let requestOptions = WebAuthn.Authentication.Options(
                challenge: randomBytes(count: 32),
                rpId: testRpId,
                allowCredentials: [.init(id: randomBytes(count: 32))]
            )

            print("Getting assertion with non-existent credential...")
            do {
                _ = try await client.getAssertion(requestOptions).value
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
        try await withReconnectableWebAuthnClient { client, reconnect in
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
            let createResponse = try await client.makeCredential(createOptions).value

            client = try await reconnect()

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
                _ = try await client.makeCredential(excludeOptions).value
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
        try await withReconnectableWebAuthnClient { client, reconnect in
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
                _ = try await client.makeCredential(createOptions).value
                client = try await reconnect()
            }

            let requestOptions = WebAuthn.Authentication.Options(
                challenge: randomBytes(count: 32),
                rpId: testRpId
            )

            print("Getting matched credentials for selection...")
            let matches = try await client.getAssertions(requestOptions).value

            #expect(matches.count >= credentialCount, "Should have at least \(credentialCount) matched credentials")
            print("Found \(matches.count) matched credentials")

            // Verify each match has credential info for selection UI
            for match in matches {
                #expect(match.id.count > 0, "Credential ID should be present")
                #expect(match.user != nil, "User info should be present for discoverable credentials")
            }

            // Select the second credential (not first) to verify selection works
            let chosenIndex = min(1, matches.count - 1)
            let chosen = matches[chosenIndex]
            print("Selecting credential at index \(chosenIndex): \(chosen.user?.name ?? "unknown")")

            let response = try await chosen.select()

            #expect(response.signature.count > 0)
            #expect(response.rawAuthenticatorData.count > 0)
            #expect(response.credentialId == chosen.id)
            #expect(response.user?.id == chosen.user?.id)
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
                pinProvider: { defaultTestPin },
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
                _ = try await client.makeCredential(options).value
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
                pinProvider: { defaultTestPin },
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
                _ = try await client.makeCredential(options).value
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
                pinProvider: { "wrongpin123" },
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
                _ = try await client.makeCredential(options).value
                Issue.record("Should have thrown invalidPIN error")
            } catch let error as WebAuthn.ClientError {
                guard case .invalidPIN(let retries, _) = error else {
                    Issue.record("Expected invalidPIN error, got: \(error)")
                    return
                }
                #expect(retries < 8, "Retry counter should have decremented")
                print("Correctly received invalidPIN with \(retries) retries remaining")
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
            let response = try await client.makeCredential(options, clientData: clientData).value

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
                for try await status in await client.makeCredential(options) {
                    switch status {
                    case .processing:
                        print("Processing...")
                    case .waitingForUser(let cancel):
                        print("Waiting for user - cancelling now!")
                        await cancel()
                    case .requestingUV:
                        print("Requesting UV...")
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

// MARK: - Extension Tests

@Suite("WebAuthn Extension Full Stack Tests", .serialized)
struct WebAuthnExtensionFullStackTests {

    // MARK: - PRF Extension

    @Test("PRF - Enable at Registration and Derive Secrets at Authentication")
    func testPRF() async throws {
        try await withReconnectableWebAuthnClient { client, reconnect in
            var client = client
            let rpId = "webauthn-prf-test.example.com"

            // 1. Create credential with PRF enabled
            let createOptions = WebAuthn.Registration.Options(
                challenge: randomBytes(count: 32),
                rp: .init(id: rpId, name: "PRF Test"),
                user: .init(
                    id: randomBytes(count: 32),
                    name: "prf@example.com",
                    displayName: "PRF User"
                ),
                residentKey: .required,
                extensions: .init(prf: .enable)
            )

            print("Creating credential with PRF enabled...")
            let createResponse = try await client.makeCredential(createOptions).value

            guard case .enabled = createResponse.clientExtensionResults.prf else {
                print("PRF not supported - skipping")
                return
            }
            print("✅ PRF enabled")

            let credentialId = createResponse.credentialId
            client = try await reconnect()

            // 2. Authenticate with PRF using one secret
            let secret1 = Data(repeating: 0xAA, count: 32)

            let authOptions1 = WebAuthn.Authentication.Options(
                challenge: randomBytes(count: 32),
                rpId: rpId,
                allowCredentials: [.init(id: credentialId)],
                extensions: .init(prf: .eval(first: secret1))
            )

            print("Authenticating with PRF (one secret)...")
            let authResponse1 = try await client.getAssertion(authOptions1).value

            guard let secrets1 = authResponse1.clientExtensionResults.prf else {
                Issue.record("Expected PRF output in first assertion")
                return
            }
            #expect(secrets1.first.count == 32)
            print("✅ PRF secrets.first: \(secrets1.first.prefix(8).hexEncodedString)...")

            client = try await reconnect()

            // 3. Authenticate again with two secrets using evalByCredential
            let secret2 = Data(repeating: 0xBB, count: 32)

            let authOptions2 = WebAuthn.Authentication.Options(
                challenge: randomBytes(count: 32),
                rpId: rpId,
                allowCredentials: [.init(id: credentialId)],
                extensions: .init(
                    prf: .init(
                        eval: .init(first: secret1, second: secret2),
                        evalByCredential: [credentialId: .init(first: secret1, second: secret2)]
                    )
                )
            )

            print("Authenticating with PRF (two secrets, evalByCredential)...")
            let authResponse2 = try await client.getAssertion(authOptions2).value

            guard let secrets2 = authResponse2.clientExtensionResults.prf else {
                Issue.record("Expected PRF output in second assertion")
                return
            }

            // Same secret1 should produce same output
            #expect(secrets2.first == secrets1.first, "Same secret should produce same output")
            #expect(secrets2.second != nil, "Should have second output")
            #expect(secrets2.second != secrets2.first, "Different secrets should produce different outputs")

            print("✅ PRF evalByCredential verified")
        }
    }

    @Test("PRF MC - Derive Secrets at Registration (CTAP2.2)")
    func testPRFMakeCredential() async throws {
        try await withReconnectableWebAuthnClient { client, reconnect in
            var client = client
            let rpId = "webauthn-prf-mc-test.example.com"

            let secret1 = Data(repeating: 0xCC, count: 32)
            let secret2 = Data(repeating: 0xDD, count: 32)

            // 1. Create credential with PRF secrets
            let createOptions = WebAuthn.Registration.Options(
                challenge: randomBytes(count: 32),
                rp: .init(id: rpId, name: "PRF MC Test"),
                user: .init(
                    id: randomBytes(count: 32),
                    name: "prf-mc@example.com",
                    displayName: "PRF MC User"
                ),
                residentKey: .required,
                extensions: .init(prf: .eval(first: secret1, second: secret2))
            )

            print("Creating credential with PRF secrets...")
            let createResponse = try await client.makeCredential(createOptions).value

            guard case .secrets(let mcSecrets) = createResponse.clientExtensionResults.prf else {
                print("hmac-secret-mc not supported - skipping")
                return
            }

            #expect(mcSecrets.first.count == 32)
            #expect(mcSecrets.second?.count == 32)
            print("✅ PRF MakeCredential derived secrets")

            let credentialId = createResponse.credentialId
            client = try await reconnect()

            // 2. Authenticate with same secrets and verify determinism
            let authOptions = WebAuthn.Authentication.Options(
                challenge: randomBytes(count: 32),
                rpId: rpId,
                allowCredentials: [.init(id: credentialId)],
                extensions: .init(prf: .eval(first: secret1, second: secret2))
            )

            print("Authenticating with PRF (verifying determinism)...")
            let authResponse = try await client.getAssertion(authOptions).value

            guard let gaSecrets = authResponse.clientExtensionResults.prf else {
                Issue.record("Expected PRF output in assertion")
                return
            }

            #expect(gaSecrets == mcSecrets, "GetAssertion secrets should match MakeCredential secrets")
            print("✅ PRF outputs are deterministic")
        }
    }

    // MARK: - LargeBlob Extension

    @Test("LargeBlob - Store and Retrieve")
    func testLargeBlobStoreAndRetrieve() async throws {
        try await withReconnectableWebAuthnClient { client, reconnect in
            var client = client
            let rpId = "webauthn-largeblob-test.example.com"
            let testData = Data("Hello from WebAuthn LargeBlob test!".utf8)

            // 1. Create credential with largeBlob support
            let createOptions = WebAuthn.Registration.Options(
                challenge: randomBytes(count: 32),
                rp: .init(id: rpId, name: "LargeBlob Test"),
                user: .init(
                    id: randomBytes(count: 32),
                    name: "blob@example.com",
                    displayName: "Blob User"
                ),
                residentKey: .required,
                extensions: .init(largeBlob: .required)
            )

            print("Creating credential with largeBlob support...")
            let createResponse = try await client.makeCredential(createOptions).value

            guard createResponse.clientExtensionResults.largeBlob?.supported == true else {
                print("LargeBlob not supported - skipping")
                return
            }
            print("✅ Credential supports largeBlob")

            let credentialId = createResponse.credentialId
            client = try await reconnect()

            // 2. Write blob
            let writeOptions = WebAuthn.Authentication.Options(
                challenge: randomBytes(count: 32),
                rpId: rpId,
                allowCredentials: [.init(id: credentialId)],
                extensions: .init(largeBlob: .write(testData))
            )

            print("Writing blob...")
            let writeResponse = try await client.getAssertion(writeOptions).value

            #expect(writeResponse.clientExtensionResults.largeBlob?.written == true)
            print("✅ Blob written")

            client = try await reconnect()

            // 3. Read blob back
            let readOptions = WebAuthn.Authentication.Options(
                challenge: randomBytes(count: 32),
                rpId: rpId,
                allowCredentials: [.init(id: credentialId)],
                extensions: .init(largeBlob: .read)
            )

            print("Reading blob...")
            let readResponse = try await client.getAssertion(readOptions).value

            #expect(readResponse.clientExtensionResults.largeBlob?.blob == testData)
            print("✅ Blob retrieved and verified")

            // 4. Delete blob via CTAP (WebAuthn API doesn't expose delete)
            try await withReconnectableCTAP2Session { session, _ in
                let deleteToken = try await session.getPinUVToken(
                    using: .pin(defaultTestPin),
                    permissions: [.largeBlobWrite],
                    rpId: nil
                )

                // Get the largeBlobKey by authenticating with the extension
                let largeBlobKey = try await CTAP2.Extension.LargeBlobKey(session: session)
                let gaParams = CTAP2.GetAssertion.Parameters(
                    rpId: rpId,
                    clientDataHash: Data(repeating: 0xCD, count: 32),
                    allowList: [.init(id: credentialId)],
                    extensions: [largeBlobKey.getAssertion.input()]
                )

                let gaToken = try await session.getPinUVToken(
                    using: .pin(defaultTestPin),
                    permissions: [.getAssertion],
                    rpId: rpId
                )

                print("Getting largeBlobKey via CTAP...")
                let assertion = try await session.getAssertion(parameters: gaParams, token: gaToken).value
                guard let key = largeBlobKey.getAssertion.output(from: assertion) else {
                    Issue.record("Expected largeBlobKey from GetAssertion")
                    return
                }

                try await session.deleteBlob(key: key, token: deleteToken)
                print("✅ Blob deleted via CTAP")

                // 5. Verify blob is gone
                let deletedBlob = try await session.getBlob(key: key)
                #expect(deletedBlob == nil, "Blob should be deleted")
                print("✅ Verified blob no longer exists")
            }
        }
    }

    @Test("LargeBlob - Multiple Credentials with Independent Blobs")
    func testLargeBlobMultipleCredentials() async throws {
        try await withReconnectableWebAuthnClient { client, reconnect in
            var client = client
            let rpId = "webauthn-largeblob-multi.example.com"
            let testData1 = Data("First credential's blob".utf8)
            let testData2 = Data("Second credential's blob".utf8)

            // Create first credential
            let createOptions1 = WebAuthn.Registration.Options(
                challenge: randomBytes(count: 32),
                rp: .init(id: rpId, name: "LargeBlob Multi Test"),
                user: .init(
                    id: randomBytes(count: 32),
                    name: "user1@example.com",
                    displayName: "User 1"
                ),
                residentKey: .required,
                extensions: .init(largeBlob: .required)
            )

            print("Creating first credential...")
            let createResponse1 = try await client.makeCredential(createOptions1).value

            guard createResponse1.clientExtensionResults.largeBlob?.supported == true else {
                print("LargeBlob not supported - skipping")
                return
            }

            let credentialId1 = createResponse1.credentialId
            client = try await reconnect()

            // Write blob to first credential
            let writeOptions1 = WebAuthn.Authentication.Options(
                challenge: randomBytes(count: 32),
                rpId: rpId,
                allowCredentials: [.init(id: credentialId1)],
                extensions: .init(largeBlob: .write(testData1))
            )
            _ = try await client.getAssertion(writeOptions1).value
            print("✅ First blob written")

            client = try await reconnect()

            // Create second credential
            let createOptions2 = WebAuthn.Registration.Options(
                challenge: randomBytes(count: 32),
                rp: .init(id: rpId, name: "LargeBlob Multi Test"),
                user: .init(
                    id: randomBytes(count: 32),
                    name: "user2@example.com",
                    displayName: "User 2"
                ),
                residentKey: .required,
                extensions: .init(largeBlob: .required)
            )

            print("Creating second credential...")
            let createResponse2 = try await client.makeCredential(createOptions2).value
            let credentialId2 = createResponse2.credentialId
            client = try await reconnect()

            // Write blob to second credential
            let writeOptions2 = WebAuthn.Authentication.Options(
                challenge: randomBytes(count: 32),
                rpId: rpId,
                allowCredentials: [.init(id: credentialId2)],
                extensions: .init(largeBlob: .write(testData2))
            )
            _ = try await client.getAssertion(writeOptions2).value
            print("✅ Second blob written")

            client = try await reconnect()

            // Read back both blobs
            let readOptions1 = WebAuthn.Authentication.Options(
                challenge: randomBytes(count: 32),
                rpId: rpId,
                allowCredentials: [.init(id: credentialId1)],
                extensions: .init(largeBlob: .read)
            )
            let readResponse1 = try await client.getAssertion(readOptions1).value
            #expect(readResponse1.clientExtensionResults.largeBlob?.blob == testData1)

            client = try await reconnect()

            let readOptions2 = WebAuthn.Authentication.Options(
                challenge: randomBytes(count: 32),
                rpId: rpId,
                allowCredentials: [.init(id: credentialId2)],
                extensions: .init(largeBlob: .read)
            )
            let readResponse2 = try await client.getAssertion(readOptions2).value
            #expect(readResponse2.clientExtensionResults.largeBlob?.blob == testData2)

            print("✅ Both blobs retrieved and verified independently")
        }
    }

    @Test("LargeBlob - Storage Full Error")
    func testLargeBlobStorageFull() async throws {
        try await withReconnectableWebAuthnClient { client, reconnect in
            var client = client
            let rpId = "webauthn-largeblob-full.example.com"

            // First create a credential with largeBlob support
            let createOptions = WebAuthn.Registration.Options(
                challenge: randomBytes(count: 32),
                rp: .init(id: rpId, name: "LargeBlob Full Test"),
                user: .init(
                    id: randomBytes(count: 32),
                    name: "full@example.com",
                    displayName: "Full User"
                ),
                residentKey: .required,
                extensions: .init(largeBlob: .required)
            )

            print("Creating credential with largeBlob support...")
            let createResponse = try await client.makeCredential(createOptions).value

            guard createResponse.clientExtensionResults.largeBlob?.supported == true else {
                print("LargeBlob not supported - skipping")
                return
            }

            let credentialId = createResponse.credentialId
            client = try await reconnect()

            // Get max size from device info via CTAP
            let info = try await withCTAP2Session { session in
                try await session.getInfo()
            }

            guard let maxSize = info.maxSerializedLargeBlobArray else {
                print("maxSerializedLargeBlobArray not available - skipping")
                return
            }

            // Create random data that won't compress well
            let oversizedData = Data((0..<Int(maxSize)).map { _ in UInt8.random(in: 0...255) })

            let writeOptions = WebAuthn.Authentication.Options(
                challenge: randomBytes(count: 32),
                rpId: rpId,
                allowCredentials: [.init(id: credentialId)],
                extensions: .init(largeBlob: .write(oversizedData))
            )

            print("Attempting to write oversized blob (\(oversizedData.count) bytes)...")
            do {
                _ = try await client.getAssertion(writeOptions).value
                Issue.record("Expected storageFull error for oversized blob")
            } catch let error as WebAuthn.ClientError {
                guard case .storageFull = error else {
                    Issue.record("Expected storageFull error, got: \(error)")
                    return
                }
                print("✅ Correctly received storageFull error")
            }
        }
    }

    // MARK: - CredProtect Extension

    @Test("CredProtect - All Protection Levels")
    func testCredProtect() async throws {
        try await withReconnectableWebAuthnClient { client, reconnect in
            var client = client
            let rpId = "webauthn-credprotect-test.example.com"

            // Test without extension - should not return credProtect (no extensions parameter)
            let createOptionsNone = WebAuthn.Registration.Options(
                challenge: randomBytes(count: 32),
                rp: .init(id: rpId, name: "CredProtect Test"),
                user: .init(
                    id: randomBytes(count: 32),
                    name: "noext@example.com",
                    displayName: "No Extension User"
                ),
                residentKey: .discouraged
            )

            print("Creating credential without credProtect extension...")
            let createResponseNone = try await client.makeCredential(createOptionsNone).value
            #expect(createResponseNone.clientExtensionResults.credentialProtectionPolicy == nil)
            print("✅ No credProtect in response when not requested")

            client = try await reconnect()

            // Test Level 1: userVerificationOptional
            let createOptions1 = WebAuthn.Registration.Options(
                challenge: randomBytes(count: 32),
                rp: .init(id: rpId, name: "CredProtect Test"),
                user: .init(
                    id: randomBytes(count: 32),
                    name: "level1@example.com",
                    displayName: "Level 1 User"
                ),
                residentKey: .discouraged,
                extensions: .init(credentialProtectionPolicy: .userVerificationOptional)
            )

            print("Creating credential with credProtect level 1...")
            let createResponse1 = try await client.makeCredential(createOptions1).value

            if createResponse1.clientExtensionResults.credentialProtectionPolicy == nil {
                print("credProtect not supported - skipping")
                return
            }
            #expect(createResponse1.clientExtensionResults.credentialProtectionPolicy == .userVerificationOptional)
            print("✅ CredProtect level 1 confirmed")

            client = try await reconnect()

            // Test Level 2: userVerificationOptionalWithCredentialIDList
            let createOptions2 = WebAuthn.Registration.Options(
                challenge: randomBytes(count: 32),
                rp: .init(id: rpId, name: "CredProtect Test"),
                user: .init(
                    id: randomBytes(count: 32),
                    name: "level2@example.com",
                    displayName: "Level 2 User"
                ),
                residentKey: .discouraged,
                extensions: .init(credentialProtectionPolicy: .userVerificationOptionalWithCredentialIDList)
            )

            print("Creating credential with credProtect level 2...")
            let createResponse2 = try await client.makeCredential(createOptions2).value

            #expect(
                createResponse2.clientExtensionResults.credentialProtectionPolicy
                    == .userVerificationOptionalWithCredentialIDList
            )
            print("✅ CredProtect level 2 confirmed")

            client = try await reconnect()

            // Test Level 3: userVerificationRequired (requires resident key)
            let createOptions3 = WebAuthn.Registration.Options(
                challenge: randomBytes(count: 32),
                rp: .init(id: rpId, name: "CredProtect Test"),
                user: .init(
                    id: randomBytes(count: 32),
                    name: "level3@example.com",
                    displayName: "Level 3 User"
                ),
                residentKey: .required,
                extensions: .init(credentialProtectionPolicy: .userVerificationRequired)
            )

            print("Creating credential with credProtect level 3...")
            let createResponse3 = try await client.makeCredential(createOptions3).value

            #expect(createResponse3.clientExtensionResults.credentialProtectionPolicy == .userVerificationRequired)
            print("✅ CredProtect level 3 confirmed")
        }
    }

    // MARK: - CredBlob Extension

    @Test("CredBlob - Store at Registration and Retrieve at Authentication")
    func testCredBlobStoreAndRetrieve() async throws {
        try await withReconnectableWebAuthnClient { client, reconnect in
            var client = client
            let rpId = "webauthn-credblob-test.example.com"
            let testBlob = Data("Hello from CredBlob!".utf8)

            // 1. Create credential with credBlob
            let createOptions = WebAuthn.Registration.Options(
                challenge: randomBytes(count: 32),
                rp: .init(id: rpId, name: "CredBlob Test"),
                user: .init(
                    id: randomBytes(count: 32),
                    name: "credblob@example.com",
                    displayName: "CredBlob User"
                ),
                residentKey: .required,
                extensions: .init(credBlob: testBlob)
            )

            print("Creating credential with credBlob...")
            let createResponse = try await client.makeCredential(createOptions).value

            guard createResponse.clientExtensionResults.credBlobSet == true else {
                print("credBlob not supported - skipping")
                return
            }
            print("✅ CredBlob stored")

            client = try await reconnect()

            // 2. Retrieve credBlob at authentication
            let authOptions = WebAuthn.Authentication.Options(
                challenge: randomBytes(count: 32),
                rpId: rpId,
                extensions: .init(getCredBlob: true)
            )

            print("Authenticating to retrieve credBlob...")
            let authResponse = try await client.getAssertion(authOptions).value

            #expect(authResponse.clientExtensionResults.credBlob == testBlob)
            print("✅ CredBlob retrieved and verified")
        }
    }

    @Test("CredBlob - Not Returned Without Extension")
    func testCredBlobNotReturnedWithoutExtension() async throws {
        try await withReconnectableWebAuthnClient { client, reconnect in
            var client = client
            let rpId = "webauthn-credblob-noext.example.com"
            let testBlob = Data("This should not be returned".utf8)

            // 1. Create credential with credBlob
            let createOptions = WebAuthn.Registration.Options(
                challenge: randomBytes(count: 32),
                rp: .init(id: rpId, name: "CredBlob NoExt Test"),
                user: .init(
                    id: randomBytes(count: 32),
                    name: "noext@example.com",
                    displayName: "NoExt User"
                ),
                residentKey: .required,
                extensions: .init(credBlob: testBlob)
            )

            print("Creating credential with credBlob...")
            let createResponse = try await client.makeCredential(createOptions).value

            guard createResponse.clientExtensionResults.credBlobSet == true else {
                print("credBlob not supported - skipping")
                return
            }

            client = try await reconnect()

            // 2. Authenticate WITHOUT requesting credBlob (no getCredBlob: true)
            let authOptions = WebAuthn.Authentication.Options(
                challenge: randomBytes(count: 32),
                rpId: rpId
            )

            print("Authenticating without credBlob extension...")
            let authResponse = try await client.getAssertion(authOptions).value

            #expect(authResponse.clientExtensionResults.credBlob == nil)
            print("✅ CredBlob not returned without extension")
        }
    }

    @Test("CredBlob - Oversized Blob Rejected")
    func testCredBlobOversizedRejected() async throws {
        try await withCTAP2Session { session in
            guard try await CTAP2.Extension.CredBlob.isSupported(by: session) else {
                print("credBlob not supported - skipping")
                return
            }

            let info = try await session.getInfo()
            guard let maxLength = info.maxCredBlobLength else {
                print("maxCredBlobLength not available - skipping")
                return
            }

            let rpId = "webauthn-credblob-oversize.example.com"
            let oversizedBlob = Data(repeating: 0xFF, count: Int(maxLength) + 1)

            let client = WebAuthn.Client(
                session: session,
                origin: try WebAuthn.Origin("https://\(rpId)"),
                pinProvider: { defaultTestPin },
                isPublicSuffix: { _ in false }
            )

            let createOptions = WebAuthn.Registration.Options(
                challenge: randomBytes(count: 32),
                rp: .init(id: rpId, name: "CredBlob Oversize Test"),
                user: .init(
                    id: randomBytes(count: 32),
                    name: "oversize@example.com",
                    displayName: "Oversize User"
                ),
                residentKey: .required,
                extensions: .init(credBlob: oversizedBlob)
            )

            print("Attempting credential with oversized credBlob (\(oversizedBlob.count) > \(maxLength))...")
            do {
                _ = try await client.makeCredential(createOptions).value
                Issue.record("Expected error for oversized credBlob")
            } catch {
                print("✅ Correctly rejected oversized credBlob: \(error)")
            }
        }
    }

    // MARK: - MinPinLength Extension

    @Test("MinPinLength - Returns Value When RP Configured")
    func testMinPinLength() async throws {
        // This test requires authenticatorConfig to configure the RP ID first
        try await withReconnectableCTAP2Session { session, reconnectWhenOverNFC in
            var session = session

            guard try await CTAP2.Extension.MinPinLength.isSupported(by: session) else {
                print("minPinLength not supported - skipping")
                return
            }

            guard try await CTAP2.Config.isSupported(by: session) else {
                print("authenticatorConfig not supported - skipping")
                return
            }

            let info = try await session.getInfo()
            guard info.options.clientPin == true else {
                print("PIN not set - skipping")
                return
            }

            let rpId = "webauthn-minpinlength-test.example.com"

            // Configure the RP ID to receive minPinLength (requires CTAP direct call)
            let configToken = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.authenticatorConfig]
            )
            let config = try await session.config(token: configToken)
            try await config.setMinPINLength(rpIDs: [rpId])
            print("✅ RP configured for minPinLength")

            session = try await reconnectWhenOverNFC()

            // Now use WebAuthn client
            let client = WebAuthn.Client(
                session: session,
                origin: try WebAuthn.Origin("https://\(rpId)"),
                pinProvider: { defaultTestPin },
                isPublicSuffix: { _ in false }
            )

            let createOptions = WebAuthn.Registration.Options(
                challenge: randomBytes(count: 32),
                rp: .init(id: rpId, name: "MinPinLength Test"),
                user: .init(
                    id: randomBytes(count: 32),
                    name: "minpin@example.com",
                    displayName: "MinPin User"
                ),
                residentKey: .required,
                extensions: .init(minPinLength: true)
            )

            print("Creating credential with minPinLength extension...")
            let createResponse = try await client.makeCredential(createOptions).value

            guard let length = createResponse.clientExtensionResults.minPinLength else {
                Issue.record("minPinLength should be returned for configured RP")
                return
            }

            #expect(length >= 4, "minPinLength should be at least 4")
            if let infoMinPinLength = info.minPinLength {
                #expect(length == infoMinPinLength)
            }
            print("✅ minPinLength returned: \(length)")
        }
    }
}

// MARK: - Helpers

private func randomBytes(count: Int) -> Data {
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
            pinProvider: { defaultTestPin },
            isPublicSuffix: { _ in false }
        )
        return try await body(client)
    }
}

private func withReconnectableWebAuthnClient<T>(
    _ body: (
        _ client: WebAuthn.Client,
        _ reconnect: () async throws -> WebAuthn.Client
    ) async throws -> T
) async throws -> T {
    try await withReconnectableCTAP2Session { session, reconnectSession in
        let client = WebAuthn.Client(
            session: session,
            origin: testOrigin,
            pinProvider: { defaultTestPin },
            isPublicSuffix: { _ in false }
        )

        let reconnect: () async throws -> WebAuthn.Client = {
            let newSession = try await reconnectSession()
            return WebAuthn.Client(
                session: newSession,
                origin: testOrigin,
                pinProvider: { defaultTestPin },
                isPublicSuffix: { _ in false }
            )
        }

        return try await body(client, reconnect)
    }
}
