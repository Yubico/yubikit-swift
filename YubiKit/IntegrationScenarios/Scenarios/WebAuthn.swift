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
import YubiKit

/// WebAuthn `Client` scenarios.
public enum WebAuthnScenario: CaseIterable {

    case makeCredentialGetAssertion
    case allowCredentials
    case allowListNoMatch
    case excludeCredentials
    case multipleCredentialsCeremony
    case rpIdMismatch
    case publicSuffixRejected
    case wrongPin
    case clientDataJSON
    case statusStream
    case discoverableNoCredentials
    case prefetchedPinMakeCredential
    case prefetchedPinGetAssertion
    case cancelMakeCredential
    case allLevels
    case derive
    case makeCredential
    case storeRetrieveLargeBlob
    case multipleCredentialsLargeBlob
    case storageFull
    case storeRetrieveCredBlob
    case notReturnedWithoutExtension
    case oversizedRejected
    case discoverable
    case nonDiscoverable
    case notRequested
    case returnsValue
    case noOutputWithoutInput
    case generateKey
    case echoedFalse
    case echoedTrue

    public var scenario: Scenario {
        switch self {
        // MARK: - Ceremonies (make / get via Client)
        case .makeCredentialGetAssertion:
            return Scenario(
                "WebAuthn.Ceremony.makeCredentialGetAssertion",
                "makeCredential then getAssertion round-trips a discoverable credential",
                requirements: Requirements(capabilities: [.fido2])
            ) { context in
                try await ensurePinSet(context)
                let client = try await context.webAuthnClient()
                let userId = randomBytes(count: 32)

                let createOptions = WebAuthn.Registration.Options(
                    challenge: randomBytes(count: 32),
                    rp: .init(id: testRpId, name: testRpName),
                    user: .init(id: userId, name: "test@example.com", displayName: "Test User"),
                    residentKey: .required
                )

                context.touch("Touch the key to create a credential")
                let createResponse = try await client.makeCredential(createOptions, authorization: .pin(defaultTestPin))
                    .value

                context.expect(createResponse.credentialId.count > 0, "credentialId should be present")
                // The public response exposes authenticator data as raw bytes.
                context.expect(createResponse.rawAuthenticatorData.count > 0, "authenticator data should be present")

                let requestOptions = WebAuthn.Authentication.Options(
                    challenge: randomBytes(count: 32),
                    rpId: testRpId
                )

                context.touch("Touch the key to authenticate")
                let assertResponse = try await assertionAfterNFCReconnect(
                    context,
                    options: requestOptions,
                    matching: createResponse.credentialId,
                )

                context.expect(assertResponse.rawAuthenticatorData.count > 0, "authenticator data should be present")
                context.expect(assertResponse.signature.count > 0, "signature should be present")
                context.expect(assertResponse.user?.id == userId, "asserted user id should match")
            }
        case .allowCredentials:
            return Scenario(
                "WebAuthn.Ceremony.allowCredentials",
                "getAssertion honors a matching allow-list entry",
                requirements: Requirements(capabilities: [.fido2])
            ) { context in
                try await ensurePinSet(context)
                let client = try await context.webAuthnClient()

                let createOptions = WebAuthn.Registration.Options(
                    challenge: randomBytes(count: 32),
                    rp: .init(id: testRpId, name: testRpName),
                    user: .init(id: randomBytes(count: 32), name: "allow@example.com", displayName: "Allow User"),
                    residentKey: .required
                )

                context.touch("Touch the key to create a credential")
                let createResponse = try await client.makeCredential(createOptions, authorization: .pin(defaultTestPin))
                    .value

                let requestOptions = WebAuthn.Authentication.Options(
                    challenge: randomBytes(count: 32),
                    rpId: testRpId,
                    allowCredentials: [.init(id: createResponse.credentialId)]
                )

                context.touch("Touch the key to authenticate")
                let authClient = try await context.webAuthnClientAfterNFCReconnect()
                let matches = try await authClient.getAssertion(
                    requestOptions,
                    authorization: .pin(defaultTestPin)
                ).value
                let assertResponse = try context.require(matches.first, "should have at least one assertion")

                context.expect(assertResponse.credentialId == createResponse.credentialId, "credentialId should match")
                context.expect(assertResponse.signature.count > 0, "signature should be present")
            }
        case .allowListNoMatch:
            return Scenario(
                "WebAuthn.Ceremony.allowListNoMatch",
                "getAssertion with an unknown allow-list entry throws noCredentials",
                requirements: Requirements(capabilities: [.fido2])
            ) { context in
                try await ensurePinSet(context)
                let client = try await context.webAuthnClient()

                let requestOptions = WebAuthn.Authentication.Options(
                    challenge: randomBytes(count: 32),
                    rpId: testRpId,
                    allowCredentials: [.init(id: randomBytes(count: 32))]
                )

                context.touch("Touch the key to authenticate")
                do {
                    _ = try await client.getAssertion(requestOptions, authorization: .pin(defaultTestPin)).value
                    context.record("Should have thrown noCredentials error")
                } catch let error as WebAuthn.ClientError {
                    if case .noCredentials = error {
                        context.log("Correctly received noCredentials error")
                    } else {
                        context.record("Expected noCredentials error, got: \(error)")
                    }
                }
            }
        case .excludeCredentials:
            return Scenario(
                "WebAuthn.Ceremony.excludeCredentials",
                "makeCredential rejects a credential already in the exclude list",
                requirements: Requirements(capabilities: [.fido2])
            ) { context in
                try await ensurePinSet(context)
                let client = try await context.webAuthnClient()

                let createOptions = WebAuthn.Registration.Options(
                    challenge: randomBytes(count: 32),
                    rp: .init(id: testRpId, name: testRpName),
                    user: .init(id: randomBytes(count: 32), name: "exclude@example.com", displayName: "Exclude User"),
                    residentKey: .required
                )

                context.touch("Touch the key to create the initial credential")
                let createResponse = try await client.makeCredential(createOptions, authorization: .pin(defaultTestPin))
                    .value

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

                context.touch("Touch the key for the excluded credential attempt")
                do {
                    let excludeClient = try await context.webAuthnClientAfterNFCReconnect()
                    _ = try await excludeClient.makeCredential(
                        excludeOptions,
                        authorization: .pin(defaultTestPin)
                    ).value
                    context.record("Should have thrown credentialExcluded error")
                } catch let error as WebAuthn.ClientError {
                    if case .credentialExcluded = error {
                        context.log("Correctly received credentialExcluded error")
                    } else {
                        context.record("Expected credentialExcluded error, got: \(error)")
                    }
                }
            }
        case .multipleCredentialsCeremony:
            return Scenario(
                "WebAuthn.Ceremony.multipleCredentials",
                "getAssertion returns one match per discoverable credential for selection",
                requirements: Requirements(capabilities: [.fido2])
            ) { context in
                try await ensurePinSet(context)
                var client = try await context.webAuthnClient()
                let credentialCount = 3

                for i in 0..<credentialCount {
                    let userId = randomBytes(count: 32)

                    let createOptions = WebAuthn.Registration.Options(
                        challenge: randomBytes(count: 32),
                        rp: .init(id: testRpId, name: testRpName),
                        user: .init(id: userId, name: "user\(i)@example.com", displayName: "User \(i)"),
                        residentKey: .required
                    )

                    context.touch("Touch the key to create credential \(i + 1)/\(credentialCount)")
                    if i > 0 {
                        client = try await context.webAuthnClientAfterNFCReconnect()
                    }
                    _ = try await client.makeCredential(createOptions, authorization: .pin(defaultTestPin)).value
                }

                let requestOptions = WebAuthn.Authentication.Options(
                    challenge: randomBytes(count: 32),
                    rpId: testRpId
                )

                context.touch("Touch the key to enumerate credentials")
                client = try await context.webAuthnClientAfterNFCReconnect()
                let matches = try await client.getAssertion(requestOptions, authorization: .pin(defaultTestPin)).value

                context.expect(
                    matches.count >= credentialCount,
                    "Should have at least \(credentialCount) matched credentials"
                )

                for match in matches {
                    context.expect(match.credentialId.count > 0, "Credential ID should be present")
                    context.expect(match.user != nil, "User info should be present for discoverable credentials")
                }

                // Pick the second match (not the first) to prove selection isn't hard-wired to index 0.
                let chosenIndex = min(1, matches.count - 1)
                let chosen = matches[chosenIndex]
                context.log("Selecting credential at index \(chosenIndex): \(chosen.user?.name ?? "unknown")")

                context.expect(chosen.signature.count > 0, "signature should be present")
                context.expect(chosen.rawAuthenticatorData.count > 0, "authenticator data should be present")
            }
        case .rpIdMismatch:
            return Scenario(
                "WebAuthn.Ceremony.rpIdMismatch",
                "makeCredential rejects an RP ID that doesn't match the origin",
                requirements: Requirements(capabilities: [.fido2])
            ) { context in
                // Fails at client-side RP ID validation before reaching the authenticator, so no PIN needed.
                let client = try await context.webAuthnClient()

                let options = WebAuthn.Registration.Options(
                    challenge: randomBytes(count: 32),
                    rp: .init(id: "other.com", name: "Other RP"),
                    user: .init(id: randomBytes(count: 32), name: "test@other.com", displayName: "Test User")
                )

                do {
                    _ = try await client.makeCredential(options, authorization: .pin(defaultTestPin)).value
                    context.record("Should have thrown invalidRequest error")
                } catch let error as WebAuthn.ClientError {
                    if case .invalidRequest(let message, _) = error {
                        context.expect(message.contains("other.com"), "message should mention the mismatched RP ID")
                        context.log("Correctly rejected mismatched RP ID: \(message)")
                    } else {
                        context.record("Expected invalidRequest error, got: \(error)")
                    }
                }
            }
        case .publicSuffixRejected:
            return Scenario(
                "WebAuthn.Ceremony.publicSuffixRejected",
                "makeCredential rejects an RP ID that is a public suffix",
                requirements: Requirements(capabilities: [.fido2])
            ) { context in
                // Fails at client-side RP ID validation before reaching the authenticator, so no PIN needed.
                let session = try await context.ctap2Session()
                let client = WebAuthn.Client(
                    session: session,
                    origin: try WebAuthn.Origin("https://mysite.co.uk"),
                    isPublicSuffix: { $0 == "co.uk" }
                )

                let options = WebAuthn.Registration.Options(
                    challenge: randomBytes(count: 32),
                    rp: .init(id: "co.uk", name: "Bad RP"),
                    user: .init(id: randomBytes(count: 32), name: "test@mysite.co.uk", displayName: "Test User")
                )

                do {
                    _ = try await client.makeCredential(options, authorization: .pin(defaultTestPin)).value
                    context.record("Should have thrown invalidRequest error")
                } catch let error as WebAuthn.ClientError {
                    if case .invalidRequest(let message, _) = error {
                        context.expect(message.contains("public suffix"), "message should mention public suffix")
                        context.log("Correctly rejected public suffix RP ID: \(message)")
                    } else {
                        context.record("Expected invalidRequest error, got: \(error)")
                    }
                }
            }
        case .wrongPin:
            return Scenario(
                "WebAuthn.Ceremony.wrongPin",
                "makeCredential with the wrong PIN throws pinRejected and decrements retries",
                requirements: Requirements(capabilities: [.fido2])
            ) { context in
                try await ensurePinSet(context)
                let client = try await context.webAuthnClient()

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

                do {
                    _ = try await client.makeCredential(options, authorization: .pin("wrongpin123")).value
                    context.record("Should have thrown pinRejected error")
                } catch let error as WebAuthn.ClientError {
                    if case .pinRejected(let retries, _) = error {
                        context.expect(retries < 8, "Retry counter should have decremented")
                        context.log("Correctly received pinRejected with \(retries) retries remaining")
                    } else {
                        context.record("Expected pinRejected error, got: \(error)")
                    }
                }
            }
        case .clientDataJSON:
            return Scenario(
                "WebAuthn.Ceremony.clientDataJSON",
                "clientDataJSON serializes with spec key ordering",
                requirements: Requirements(capabilities: [.fido2])
            ) { context in
                try await ensurePinSet(context)
                let client = try await context.webAuthnClient()
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
                    origin: try WebAuthn.Origin(testOrigin),
                    rpId: testRpId,
                    crossOrigin: false
                )

                context.touch("Touch the key to create a credential")
                let response = try await client.makeCredential(
                    options,
                    clientData: clientData,
                    authorization: .pin(defaultTestPin)
                ).value

                // Recover the serialized clientDataJSON from the public JSON envelope.
                let envelope = try JSONSerialization.jsonObject(with: response.toJSON(), options: []) as? [String: Any]
                let inner = envelope?["response"] as? [String: Any]
                let clientDataB64 = try context.require(
                    inner?["clientDataJSON"] as? String,
                    "clientDataJSON should be present in toJSON output"
                )
                let clientDataJSON = try context.require(
                    decodeBase64URL(clientDataB64),
                    "clientDataJSON should base64url-decode"
                )
                let jsonString = try context.require(
                    String(data: clientDataJSON, encoding: .utf8),
                    "clientDataJSON should be valid UTF-8"
                )
                context.log("clientDataJSON: \(jsonString)")

                context.expect(jsonString.contains("\"type\""), "should contain type")
                context.expect(jsonString.contains("\"challenge\""), "should contain challenge")
                context.expect(jsonString.contains("\"origin\""), "should contain origin")
                context.expect(jsonString.contains("\"crossOrigin\""), "should contain crossOrigin")
                context.expect(jsonString.contains("webauthn.create"), "should contain webauthn.create")
                context.expect(jsonString.contains("example.com"), "should contain example.com")

                // Verify key ordering per WebAuthn spec: type, challenge, origin, crossOrigin.
                let typeIndex = try context.require(jsonString.range(of: "\"type\"")?.lowerBound, "type key present")
                let challengeIndex = try context.require(
                    jsonString.range(of: "\"challenge\"")?.lowerBound,
                    "challenge key present"
                )
                let originIndex = try context.require(
                    jsonString.range(of: "\"origin\"")?.lowerBound,
                    "origin key present"
                )
                let crossOriginIndex = try context.require(
                    jsonString.range(of: "\"crossOrigin\"")?.lowerBound,
                    "crossOrigin key present"
                )
                context.expect(typeIndex < challengeIndex, "type should come before challenge")
                context.expect(challengeIndex < originIndex, "challenge should come before origin")
                context.expect(originIndex < crossOriginIndex, "origin should come before crossOrigin")
            }
        case .statusStream:
            return Scenario(
                "WebAuthn.Ceremony.statusStream",
                "getAssertion status stream delivers user-presence events and pulls the PIN via closure",
                requirements: Requirements(capabilities: [.fido2])
            ) { context in
                try await ensurePinSet(context)
                let client = try await context.webAuthnClient()

                let createOptions = WebAuthn.Registration.Options(
                    challenge: randomBytes(count: 32),
                    rp: .init(id: testRpId, name: testRpName),
                    user: .init(id: randomBytes(count: 32), name: "stream@example.com", displayName: "Stream User"),
                    residentKey: .required
                )

                context.touch("Touch the key to create a credential")
                _ = try await client.makeCredential(createOptions, authorization: .pin(defaultTestPin)).value

                let requestOptions = WebAuthn.Authentication.Options(
                    challenge: randomBytes(count: 32),
                    rpId: testRpId
                )

                let pinAsks = Box(0)
                var sawWaitingForUser = false
                var matches: [WebAuthn.Authentication.Response]?

                context.touch("Touch the key to authenticate")
                let authClient = try await context.webAuthnClientAfterNFCReconnect()
                let stream = await authClient.getAssertion(
                    requestOptions,
                    authorization: .init(
                        providePIN: {
                            pinAsks.value += 1
                            return .pin(defaultTestPin)
                        },
                        uv: .skipped
                    )
                )
                for try await status in stream {
                    switch status {
                    case .processing:
                        break
                    case .waitingForUser:
                        sawWaitingForUser = true
                    case .waitingForUserVerification:
                        context.record("UV should be skipped under .pin authorization")
                    case .finished(let result):
                        matches = result
                    }
                }

                context.expect(pinAsks.value == 1, "PIN closure should have been invoked exactly once")
                context.expect(sawWaitingForUser, "Stream should have delivered waitingForUser")
                let resolved = try context.require(matches, "Stream should have delivered .finished with matches")
                context.expect(!resolved.isEmpty, "Should have at least one matched credential")
                context.expect((resolved.first?.signature.count ?? 0) > 0, "signature should be present")
            }
        case .discoverableNoCredentials:
            return Scenario(
                "WebAuthn.Ceremony.discoverableNoCredentials",
                "discoverable getAssertion for an RP with no credentials throws noCredentials",
                requirements: Requirements(capabilities: [.fido2])
            ) { context in
                try await ensurePinSet(context)
                let unusedRpId = "no-creds-\(UUID().uuidString.prefix(8)).example.com"
                let client = try await context.webAuthnClient(origin: "https://\(unusedRpId)")

                let requestOptions = WebAuthn.Authentication.Options(
                    challenge: randomBytes(count: 32),
                    rpId: unusedRpId
                )

                context.touch("Touch the key to authenticate")
                do {
                    _ = try await client.getAssertion(requestOptions, authorization: .pin(defaultTestPin)).value
                    context.record("Should have thrown noCredentials error")
                } catch let error as WebAuthn.ClientError {
                    if case .noCredentials = error {
                        context.log("Correctly received noCredentials error for discoverable path")
                    } else {
                        context.record("Expected noCredentials error, got: \(error)")
                    }
                }
            }
        case .prefetchedPinMakeCredential:
            return Scenario(
                "WebAuthn.Ceremony.prefetchedPinMakeCredential",
                "makeCredential consumes a pre-supplied PIN silently while still emitting waitingForUser",
                requirements: Requirements(capabilities: [.fido2])
            ) { context in
                try await ensurePinSet(context)
                let client = try await context.webAuthnClient()

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

                var sawWaitingForUser = false
                var finished = false

                context.touch("Touch the key to create a credential")
                for try await status in await client.makeCredential(options, authorization: .pin(defaultTestPin)) {
                    switch status {
                    case .processing:
                        break
                    case .waitingForUser:
                        sawWaitingForUser = true
                    case .waitingForUserVerification:
                        context.record("UV should be skipped under .pin authorization")
                    case .finished:
                        finished = true
                    }
                }

                context.expect(sawWaitingForUser, "Stream should still deliver waitingForUser")
                context.expect(finished, "Stream should reach .finished")
            }
        case .prefetchedPinGetAssertion:
            return Scenario(
                "WebAuthn.Ceremony.prefetchedPinGetAssertion",
                "getAssertion consumes a pre-supplied PIN silently",
                requirements: Requirements(capabilities: [.fido2])
            ) { context in
                try await ensurePinSet(context)
                let client = try await context.webAuthnClient()

                let createOptions = WebAuthn.Registration.Options(
                    challenge: randomBytes(count: 32),
                    rp: .init(id: testRpId, name: testRpName),
                    user: .init(
                        id: randomBytes(count: 32),
                        name: "prefetched-ga@example.com",
                        displayName: "Prefetched GA"
                    ),
                    residentKey: .required
                )

                context.touch("Touch the key to create a credential")
                _ = try await client.makeCredential(createOptions, authorization: .pin(defaultTestPin)).value

                let requestOptions = WebAuthn.Authentication.Options(
                    challenge: randomBytes(count: 32),
                    rpId: testRpId
                )

                var matches: [WebAuthn.Authentication.Response]?

                context.touch("Touch the key to authenticate")
                let authClient = try await context.webAuthnClientAfterNFCReconnect()
                for try await status in await authClient.getAssertion(
                    requestOptions,
                    authorization: .pin(defaultTestPin)
                ) {
                    if case .finished(let result) = status { matches = result }
                }

                let resolved = try context.require(matches, "Stream should have delivered .finished with matches")
                context.expect(!resolved.isEmpty, "should have at least one match")
                context.expect((resolved.first?.signature.count ?? 0) > 0, "signature should be present")
            }
        case .cancelMakeCredential:
            return Scenario(
                "WebAuthn.Ceremony.cancelMakeCredential",
                "makeCredential can be cancelled from the status stream",
                requirements: Requirements(capabilities: [.fido2])
            ) { context in
                try await ensurePinSet(context)
                let client = try await context.webAuthnClient()

                let options = WebAuthn.Registration.Options(
                    challenge: randomBytes(count: 32),
                    rp: .init(id: testRpId, name: testRpName),
                    user: .init(id: randomBytes(count: 32), name: "cancel@example.com", displayName: "Cancel User"),
                    residentKey: .discouraged
                )

                context.touch("Cancellation fires automatically on waitingForUser")
                do {
                    let stream = await client.makeCredential(options, authorization: .pin(defaultTestPin))
                    for try await status in stream {
                        switch status {
                        case .processing:
                            break
                        case .waitingForUser(let cancel):
                            await cancel()
                        case .waitingForUserVerification:
                            context.record("UV should be skipped under .pin authorization")
                        case .finished:
                            context.record("makeCredential should have been cancelled")
                        }
                    }
                    context.record("makeCredential should have thrown cancellation error")
                } catch let error as WebAuthn.ClientError {
                    if case .cancelled = error {
                        context.log("Cancellation successful")
                    } else {
                        context.record("Expected cancelled error, got: \(error)")
                    }
                }
            }
        // MARK: - credProtect
        case .allLevels:
            return Scenario(
                "WebAuthn.CredProtect.allLevels",
                "credProtect echoes the applied protection level for each policy",
                requirements: Requirements(capabilities: [.fido2])
            ) { context in
                try await ensurePinSet(context)
                var client = try await context.webAuthnClient()

                let createOptionsNone = WebAuthn.Registration.Options(
                    challenge: randomBytes(count: 32),
                    rp: .init(id: testRpId, name: "CredProtect Test"),
                    user: .init(
                        id: randomBytes(count: 32),
                        name: "noext@example.com",
                        displayName: "No Extension User"
                    ),
                    residentKey: .discouraged
                )

                context.touch("Touch the key (no credProtect)")
                let createResponseNone = try await client.makeCredential(
                    createOptionsNone,
                    authorization: .pin(defaultTestPin)
                ).value
                context.expect(
                    createResponseNone.clientExtensionResults.credProtect?.policy == nil,
                    "no credProtect should be returned when not requested"
                )

                let createOptions1 = WebAuthn.Registration.Options(
                    challenge: randomBytes(count: 32),
                    rp: .init(id: testRpId, name: "CredProtect Test"),
                    user: .init(id: randomBytes(count: 32), name: "level1@example.com", displayName: "Level 1 User"),
                    residentKey: .discouraged,
                    extensions: .init(credProtect: .init(policy: .userVerificationOptional))
                )

                context.touch("Touch the key (credProtect level 1)")
                client = try await context.webAuthnClientAfterNFCReconnect()
                let createResponse1 = try await client.makeCredential(
                    createOptions1,
                    authorization: .pin(defaultTestPin)
                )
                .value

                if createResponse1.clientExtensionResults.credProtect?.policy == nil {
                    try context.skip("credProtect not supported")
                }
                context.expect(
                    createResponse1.clientExtensionResults.credProtect?.policy == .userVerificationOptional,
                    "level 1 policy should be echoed"
                )

                let createOptions2 = WebAuthn.Registration.Options(
                    challenge: randomBytes(count: 32),
                    rp: .init(id: testRpId, name: "CredProtect Test"),
                    user: .init(id: randomBytes(count: 32), name: "level2@example.com", displayName: "Level 2 User"),
                    residentKey: .discouraged,
                    extensions: .init(credProtect: .init(policy: .userVerificationOptionalWithCredentialIDList))
                )

                context.touch("Touch the key (credProtect level 2)")
                client = try await context.webAuthnClientAfterNFCReconnect()
                let createResponse2 = try await client.makeCredential(
                    createOptions2,
                    authorization: .pin(defaultTestPin)
                )
                .value
                context.expect(
                    createResponse2.clientExtensionResults.credProtect?.policy
                        == .userVerificationOptionalWithCredentialIDList,
                    "level 2 policy should be echoed"
                )

                // credProtect level 3 requires a resident key.
                let createOptions3 = WebAuthn.Registration.Options(
                    challenge: randomBytes(count: 32),
                    rp: .init(id: testRpId, name: "CredProtect Test"),
                    user: .init(id: randomBytes(count: 32), name: "level3@example.com", displayName: "Level 3 User"),
                    residentKey: .required,
                    extensions: .init(credProtect: .init(policy: .userVerificationRequired))
                )

                context.touch("Touch the key (credProtect level 3)")
                client = try await context.webAuthnClientAfterNFCReconnect()
                let createResponse3 = try await client.makeCredential(
                    createOptions3,
                    authorization: .pin(defaultTestPin)
                )
                .value
                context.expect(
                    createResponse3.clientExtensionResults.credProtect?.policy == .userVerificationRequired,
                    "level 3 policy should be echoed"
                )
            }
        // MARK: - prf
        case .derive:
            return Scenario(
                "WebAuthn.PRF.derive",
                "PRF enabled at registration derives deterministic secrets at authentication",
                requirements: Requirements(capabilities: [.fido2])
            ) { context in
                try await ensurePinSet(context)
                let client = try await context.webAuthnClient()

                let createOptions = WebAuthn.Registration.Options(
                    challenge: randomBytes(count: 32),
                    rp: .init(id: testRpId, name: "PRF Test"),
                    user: .init(id: randomBytes(count: 32), name: "prf@example.com", displayName: "PRF User"),
                    residentKey: .required,
                    extensions: .init(prf: .enable)
                )

                context.touch("Touch the key to create a PRF credential")
                let createResponse = try await client.makeCredential(createOptions, authorization: .pin(defaultTestPin))
                    .value

                guard createResponse.clientExtensionResults.prf?.enabled == true else {
                    try context.skip("PRF not supported")
                }
                let credentialId = createResponse.credentialId

                let secret1 = Data(repeating: 0xAA, count: 32)
                let authOptions1 = WebAuthn.Authentication.Options(
                    challenge: randomBytes(count: 32),
                    rpId: testRpId,
                    allowCredentials: [.init(id: credentialId)],
                    extensions: .init(prf: .eval(first: secret1))
                )

                context.touch("Touch the key to derive PRF (one secret)")
                let authResponse1 = try await firstAssertionAfterNFCReconnect(context, options: authOptions1)
                let prfOutput1 = try context.require(
                    authResponse1.clientExtensionResults.prf,
                    "Expected PRF output in first assertion"
                )
                context.expect(prfOutput1.results.first.count == 32, "PRF first secret should be 32 bytes")

                let secret2 = Data(repeating: 0xBB, count: 32)
                let authOptions2 = WebAuthn.Authentication.Options(
                    challenge: randomBytes(count: 32),
                    rpId: testRpId,
                    allowCredentials: [.init(id: credentialId)],
                    extensions: .init(
                        prf: .init(
                            eval: .init(first: secret1, second: secret2),
                            evalByCredential: [credentialId: .init(first: secret1, second: secret2)]
                        )
                    )
                )

                context.touch("Touch the key to derive PRF (two secrets)")
                let authResponse2 = try await firstAssertionAfterNFCReconnect(context, options: authOptions2)
                let prfOutput2 = try context.require(
                    authResponse2.clientExtensionResults.prf,
                    "Expected PRF output in second assertion"
                )

                context.expect(
                    prfOutput2.results.first == prfOutput1.results.first,
                    "Same secret should produce same output"
                )
                context.expect(prfOutput2.results.second != nil, "Should have second output")
                context.expect(
                    prfOutput2.results.second != prfOutput2.results.first,
                    "Different secrets should produce different outputs"
                )
            }
        case .makeCredential:
            return Scenario(
                "WebAuthn.PRF.makeCredential",
                "PRF derives secrets at registration (hmac-secret-mc) deterministically",
                requirements: Requirements(capabilities: [.fido2])
            ) { context in
                try await ensurePinSet(context)
                let client = try await context.webAuthnClient()

                let secret1 = Data(repeating: 0xCC, count: 32)
                let secret2 = Data(repeating: 0xDD, count: 32)

                let createOptions = WebAuthn.Registration.Options(
                    challenge: randomBytes(count: 32),
                    rp: .init(id: testRpId, name: "PRF MC Test"),
                    user: .init(id: randomBytes(count: 32), name: "prf-mc@example.com", displayName: "PRF MC User"),
                    residentKey: .required,
                    extensions: .init(prf: .eval(first: secret1, second: secret2))
                )

                context.touch("Touch the key to create a PRF credential")
                let createResponse = try await client.makeCredential(createOptions, authorization: .pin(defaultTestPin))
                    .value

                guard let prfOutput = createResponse.clientExtensionResults.prf,
                    let mcSecrets = prfOutput.results
                else {
                    try context.skip("hmac-secret-mc not supported")
                }

                context.expect(mcSecrets.first.count == 32, "first secret should be 32 bytes")
                context.expect(mcSecrets.second?.count == 32, "second secret should be 32 bytes")

                let credentialId = createResponse.credentialId

                let authOptions = WebAuthn.Authentication.Options(
                    challenge: randomBytes(count: 32),
                    rpId: testRpId,
                    allowCredentials: [.init(id: credentialId)],
                    extensions: .init(prf: .eval(first: secret1, second: secret2))
                )

                context.touch("Touch the key to verify PRF determinism")
                let authResponse = try await firstAssertionAfterNFCReconnect(context, options: authOptions)
                let gaOutput = try context.require(
                    authResponse.clientExtensionResults.prf,
                    "Expected PRF output in assertion"
                )
                context.expect(
                    gaOutput.results == mcSecrets,
                    "GetAssertion secrets should match MakeCredential secrets"
                )
            }
        // MARK: - largeBlobs
        case .storeRetrieveLargeBlob:
            return Scenario(
                "WebAuthn.LargeBlob.storeRetrieve",
                "largeBlob stores and retrieves data, then deletes it via CTAP",
                requirements: Requirements(capabilities: [.fido2])
            ) { context in
                try await ensurePinSet(context)
                var session = try await context.ctap2Session()
                var client = WebAuthn.Client(
                    session: session,
                    origin: try WebAuthn.Origin(testOrigin),
                    isPublicSuffix: { _ in false }
                )
                let testData = Data("Hello from WebAuthn LargeBlob test!".utf8)

                let createOptions = WebAuthn.Registration.Options(
                    challenge: randomBytes(count: 32),
                    rp: .init(id: testRpId, name: "LargeBlob Test"),
                    user: .init(id: randomBytes(count: 32), name: "blob@example.com", displayName: "Blob User"),
                    residentKey: .required,
                    extensions: .init(largeBlob: .required)
                )

                context.touch("Touch the key to create a largeBlob credential")
                let createResponse = try await client.makeCredential(createOptions, authorization: .pin(defaultTestPin))
                    .value

                guard createResponse.clientExtensionResults.largeBlob?.supported == true else {
                    try context.skip("LargeBlob not supported")
                }
                let credentialId = createResponse.credentialId

                let writeOptions = WebAuthn.Authentication.Options(
                    challenge: randomBytes(count: 32),
                    rpId: testRpId,
                    allowCredentials: [.init(id: credentialId)],
                    extensions: .init(largeBlob: .write(testData))
                )
                context.touch("Touch the key to write the blob")
                client = try await context.webAuthnClientAfterNFCReconnect()
                let writeResponse = try await firstAssertion(from: client, options: writeOptions, context)
                context.expect(
                    writeResponse.clientExtensionResults.largeBlob?.written == true,
                    "blob should be written"
                )

                let readOptions = WebAuthn.Authentication.Options(
                    challenge: randomBytes(count: 32),
                    rpId: testRpId,
                    allowCredentials: [.init(id: credentialId)],
                    extensions: .init(largeBlob: .read)
                )
                context.touch("Touch the key to read the blob")
                client = try await context.webAuthnClientAfterNFCReconnect()
                let readResponse = try await firstAssertion(from: client, options: readOptions, context)
                context.expect(
                    readResponse.clientExtensionResults.largeBlob?.blob == testData,
                    "blob should round-trip"
                )

                // Delete blob via CTAP (the WebAuthn API doesn't expose delete).
                context.touch("Touch the key to fetch the largeBlobKey")
                session = try await context.ctap2SessionAfterNFCReconnect()
                _ = try await session.getPinUVToken(
                    using: .pin(defaultTestPin),
                    permissions: [.largeBlobWrite],
                    rpId: nil
                )

                let largeBlobKey = try await CTAP2.Extension.LargeBlobKey(session: session)
                let gaParams = CTAP2.GetAssertion.Parameters(
                    rpId: testRpId,
                    clientDataHash: Data(repeating: 0xCD, count: 32),
                    allowList: [.init(id: credentialId)],
                    extensions: [largeBlobKey.getAssertion.input()]
                )
                let gaToken = try await session.getPinUVToken(
                    using: .pin(defaultTestPin),
                    permissions: [.getAssertion],
                    rpId: testRpId
                )

                let assertion = try await session.getAssertion(parameters: gaParams, token: gaToken).value
                let key = try context.require(
                    largeBlobKey.getAssertion.output(from: assertion),
                    "Expected largeBlobKey from GetAssertion"
                )

                let deleteToken = try await session.getPinUVToken(
                    using: .pin(defaultTestPin),
                    permissions: [.largeBlobWrite],
                    rpId: nil
                )
                try await session.deleteBlob(key: key, token: deleteToken)

                let deletedBlob = try await session.getBlob(key: key)
                context.expect(deletedBlob == nil, "Blob should be deleted")
            }
        case .multipleCredentialsLargeBlob:
            return Scenario(
                "WebAuthn.LargeBlob.multipleCredentials",
                "largeBlob keeps independent blobs per credential",
                requirements: Requirements(capabilities: [.fido2])
            ) { context in
                try await ensurePinSet(context)
                var client = try await context.webAuthnClient()
                let testData1 = Data("First credential's blob".utf8)
                let testData2 = Data("Second credential's blob".utf8)

                let createOptions1 = WebAuthn.Registration.Options(
                    challenge: randomBytes(count: 32),
                    rp: .init(id: testRpId, name: "LargeBlob Multi Test"),
                    user: .init(id: randomBytes(count: 32), name: "user1@example.com", displayName: "User 1"),
                    residentKey: .required,
                    extensions: .init(largeBlob: .required)
                )

                context.touch("Touch the key to create credential 1")
                let createResponse1 = try await client.makeCredential(
                    createOptions1,
                    authorization: .pin(defaultTestPin)
                )
                .value
                guard createResponse1.clientExtensionResults.largeBlob?.supported == true else {
                    try context.skip("LargeBlob not supported")
                }
                let credentialId1 = createResponse1.credentialId

                let writeOptions1 = WebAuthn.Authentication.Options(
                    challenge: randomBytes(count: 32),
                    rpId: testRpId,
                    allowCredentials: [.init(id: credentialId1)],
                    extensions: .init(largeBlob: .write(testData1))
                )
                context.touch("Touch the key to write blob 1")
                client = try await context.webAuthnClientAfterNFCReconnect()
                _ = try await client.getAssertion(writeOptions1, authorization: .pin(defaultTestPin)).value

                let createOptions2 = WebAuthn.Registration.Options(
                    challenge: randomBytes(count: 32),
                    rp: .init(id: testRpId, name: "LargeBlob Multi Test"),
                    user: .init(id: randomBytes(count: 32), name: "user2@example.com", displayName: "User 2"),
                    residentKey: .required,
                    extensions: .init(largeBlob: .required)
                )
                context.touch("Touch the key to create credential 2")
                client = try await context.webAuthnClientAfterNFCReconnect()
                let createResponse2 = try await client.makeCredential(
                    createOptions2,
                    authorization: .pin(defaultTestPin)
                )
                .value
                let credentialId2 = createResponse2.credentialId

                let writeOptions2 = WebAuthn.Authentication.Options(
                    challenge: randomBytes(count: 32),
                    rpId: testRpId,
                    allowCredentials: [.init(id: credentialId2)],
                    extensions: .init(largeBlob: .write(testData2))
                )
                context.touch("Touch the key to write blob 2")
                client = try await context.webAuthnClientAfterNFCReconnect()
                _ = try await client.getAssertion(writeOptions2, authorization: .pin(defaultTestPin)).value

                let readOptions1 = WebAuthn.Authentication.Options(
                    challenge: randomBytes(count: 32),
                    rpId: testRpId,
                    allowCredentials: [.init(id: credentialId1)],
                    extensions: .init(largeBlob: .read)
                )
                context.touch("Touch the key to read blob 1")
                let readResponse1 = try await firstAssertionAfterNFCReconnect(context, options: readOptions1)
                context.expect(readResponse1.clientExtensionResults.largeBlob?.blob == testData1, "blob 1 should match")

                let readOptions2 = WebAuthn.Authentication.Options(
                    challenge: randomBytes(count: 32),
                    rpId: testRpId,
                    allowCredentials: [.init(id: credentialId2)],
                    extensions: .init(largeBlob: .read)
                )
                context.touch("Touch the key to read blob 2")
                let readResponse2 = try await firstAssertionAfterNFCReconnect(context, options: readOptions2)
                context.expect(readResponse2.clientExtensionResults.largeBlob?.blob == testData2, "blob 2 should match")
            }
        case .storageFull:
            return Scenario(
                "WebAuthn.LargeBlob.storageFull",
                "largeBlob write rejects an oversized blob with storageFull",
                requirements: Requirements(capabilities: [.fido2])
            ) { context in
                try await ensurePinSet(context)
                let client = try await context.webAuthnClient()

                let createOptions = WebAuthn.Registration.Options(
                    challenge: randomBytes(count: 32),
                    rp: .init(id: testRpId, name: "LargeBlob Full Test"),
                    user: .init(id: randomBytes(count: 32), name: "full@example.com", displayName: "Full User"),
                    residentKey: .required,
                    extensions: .init(largeBlob: .required)
                )

                context.touch("Touch the key to create a largeBlob credential")
                let createResponse = try await client.makeCredential(createOptions, authorization: .pin(defaultTestPin))
                    .value
                guard createResponse.clientExtensionResults.largeBlob?.supported == true else {
                    try context.skip("LargeBlob not supported")
                }
                let credentialId = createResponse.credentialId

                // 1MB of random data — guaranteed to exceed any YubiKey's ~4KB largeBlob storage.
                let oversizedData = Data((0..<1_000_000).map { _ in UInt8.random(in: 0...255) })
                let writeOptions = WebAuthn.Authentication.Options(
                    challenge: randomBytes(count: 32),
                    rpId: testRpId,
                    allowCredentials: [.init(id: credentialId)],
                    extensions: .init(largeBlob: .write(oversizedData))
                )

                context.touch("Touch the key to attempt the oversized write")
                do {
                    let writeClient = try await context.webAuthnClientAfterNFCReconnect()
                    _ = try await writeClient.getAssertion(writeOptions, authorization: .pin(defaultTestPin)).value
                    context.record("Expected storageFull error for oversized blob")
                } catch let error as WebAuthn.ClientError {
                    if case .storageFull = error {
                        context.log("Correctly received storageFull error")
                    } else {
                        context.record("Expected storageFull error, got: \(error)")
                    }
                }
            }
        // MARK: - credBlob
        case .storeRetrieveCredBlob:
            return Scenario(
                "WebAuthn.CredBlob.storeRetrieve",
                "credBlob stored at registration is retrieved at authentication",
                requirements: Requirements(capabilities: [.fido2])
            ) { context in
                try await ensurePinSet(context)
                let client = try await context.webAuthnClient()
                let testBlob = Data("Hello from CredBlob!".utf8)

                let createOptions = WebAuthn.Registration.Options(
                    challenge: randomBytes(count: 32),
                    rp: .init(id: testRpId, name: "CredBlob Test"),
                    user: .init(id: randomBytes(count: 32), name: "credblob@example.com", displayName: "CredBlob User"),
                    residentKey: .required,
                    extensions: .init(credBlob: testBlob)
                )

                context.touch("Touch the key to store the credBlob")
                let createResponse = try await client.makeCredential(createOptions, authorization: .pin(defaultTestPin))
                    .value
                guard createResponse.clientExtensionResults.credBlob?.stored == true else {
                    try context.skip("credBlob not supported")
                }

                let authOptions = WebAuthn.Authentication.Options(
                    challenge: randomBytes(count: 32),
                    rpId: testRpId,
                    extensions: .init(getCredBlob: true)
                )

                context.touch("Touch the key to retrieve the credBlob")
                let authResponse = try await assertionAfterNFCReconnect(
                    context,
                    options: authOptions,
                    matching: createResponse.credentialId,
                )
                context.expect(
                    authResponse.clientExtensionResults.credBlob?.blob == testBlob,
                    "credBlob should round-trip"
                )
            }
        case .notReturnedWithoutExtension:
            return Scenario(
                "WebAuthn.CredBlob.notReturnedWithoutExtension",
                "credBlob is not returned when not requested at authentication",
                requirements: Requirements(capabilities: [.fido2])
            ) { context in
                try await ensurePinSet(context)
                let client = try await context.webAuthnClient()
                let testBlob = Data("This should not be returned".utf8)

                let createOptions = WebAuthn.Registration.Options(
                    challenge: randomBytes(count: 32),
                    rp: .init(id: testRpId, name: "CredBlob NoExt Test"),
                    user: .init(id: randomBytes(count: 32), name: "noext@example.com", displayName: "NoExt User"),
                    residentKey: .required,
                    extensions: .init(credBlob: testBlob)
                )

                context.touch("Touch the key to store the credBlob")
                let createResponse = try await client.makeCredential(createOptions, authorization: .pin(defaultTestPin))
                    .value
                guard createResponse.clientExtensionResults.credBlob?.stored == true else {
                    try context.skip("credBlob not supported")
                }

                let authOptions = WebAuthn.Authentication.Options(
                    challenge: randomBytes(count: 32),
                    rpId: testRpId
                )

                context.touch("Touch the key to authenticate without credBlob")
                let authResponse = try await assertionAfterNFCReconnect(
                    context,
                    options: authOptions,
                    matching: createResponse.credentialId,
                )
                context.expect(
                    authResponse.clientExtensionResults.credBlob?.blob == nil,
                    "credBlob should not be returned without the extension"
                )
            }
        case .oversizedRejected:
            return Scenario(
                "WebAuthn.CredBlob.oversizedRejected",
                "credBlob exceeding maxCredBlobLength is rejected",
                requirements: Requirements(capabilities: [.fido2])
            ) { context in
                try await ensurePinSet(context)
                let session = try await context.ctap2Session()

                guard try await CTAP2.Extension.CredBlob.isSupported(by: session) else {
                    try context.skip("credBlob not supported")
                }
                guard let maxLength = try await session.getInfo().maxCredBlobLength else {
                    try context.skip("maxCredBlobLength not available")
                }

                let oversizedBlob = Data(repeating: 0xFF, count: Int(maxLength) + 1)
                let client = WebAuthn.Client(
                    session: session,
                    origin: try WebAuthn.Origin(testOrigin),
                    allowedExtensions: [.credBlob],
                    isPublicSuffix: { _ in false }
                )

                let createOptions = WebAuthn.Registration.Options(
                    challenge: randomBytes(count: 32),
                    rp: .init(id: testRpId, name: "CredBlob Oversize Test"),
                    user: .init(id: randomBytes(count: 32), name: "oversize@example.com", displayName: "Oversize User"),
                    residentKey: .required,
                    extensions: .init(credBlob: oversizedBlob)
                )

                context.touch("Touch the key to attempt the oversized credBlob")
                do {
                    _ = try await client.makeCredential(createOptions, authorization: .pin(defaultTestPin)).value
                    context.record("Expected error for oversized credBlob")
                } catch {
                    context.log("Correctly rejected oversized credBlob: \(error)")
                }
            }
        // MARK: - credProps
        case .discoverable:
            return Scenario(
                "WebAuthn.CredProps.discoverable",
                "credProps reports rk=true for a discoverable credential",
                requirements: Requirements(capabilities: [.fido2])
            ) { context in
                try await ensurePinSet(context)
                let client = try await credPropsClient(context)

                let options = WebAuthn.Registration.Options(
                    challenge: randomBytes(count: 32),
                    rp: .init(id: testRpId, name: "CredProps Test"),
                    user: .init(
                        id: randomBytes(count: 32),
                        name: "credprops-rk@example.com",
                        displayName: "CredProps RK"
                    ),
                    residentKey: .required,
                    extensions: .init(credProps: true)
                )

                context.touch("Touch the key to create a discoverable credential")
                let response = try await client.makeCredential(options, authorization: .pin(defaultTestPin)).value
                context.expect(response.clientExtensionResults.credProps != nil, "credProps should be present")
                context.expect(response.clientExtensionResults.credProps?.rk == true, "rk should be true")
            }
        case .nonDiscoverable:
            return Scenario(
                "WebAuthn.CredProps.nonDiscoverable",
                "credProps reports rk=false for a non-discoverable credential",
                requirements: Requirements(capabilities: [.fido2])
            ) { context in
                try await ensurePinSet(context)
                let client = try await credPropsClient(context)

                let options = WebAuthn.Registration.Options(
                    challenge: randomBytes(count: 32),
                    rp: .init(id: testRpId, name: "CredProps Test"),
                    user: .init(
                        id: randomBytes(count: 32),
                        name: "credprops-nork@example.com",
                        displayName: "CredProps No RK"
                    ),
                    residentKey: .discouraged,
                    extensions: .init(credProps: true)
                )

                context.touch("Touch the key to create a non-discoverable credential")
                let response = try await client.makeCredential(options, authorization: .pin(defaultTestPin)).value
                context.expect(response.clientExtensionResults.credProps != nil, "credProps should be present")
                context.expect(response.clientExtensionResults.credProps?.rk == false, "rk should be false")
            }
        case .notRequested:
            return Scenario(
                "WebAuthn.CredProps.notRequested",
                "credProps is nil when not requested",
                requirements: Requirements(capabilities: [.fido2])
            ) { context in
                try await ensurePinSet(context)
                let client = try await credPropsClient(context)

                let options = WebAuthn.Registration.Options(
                    challenge: randomBytes(count: 32),
                    rp: .init(id: testRpId, name: "CredProps Test"),
                    user: .init(
                        id: randomBytes(count: 32),
                        name: "credprops-none@example.com",
                        displayName: "CredProps None"
                    ),
                    residentKey: .required
                )

                context.touch("Touch the key to create a credential")
                let response = try await client.makeCredential(options, authorization: .pin(defaultTestPin)).value
                context.expect(
                    response.clientExtensionResults.credProps == nil,
                    "credProps should be nil when not requested"
                )
            }
        // MARK: - minPinLength
        case .returnsValue:
            return Scenario(
                "WebAuthn.MinPinLength.returnsValue",
                "minPinLength returns the enforced length once the RP is configured",
                requirements: Requirements(capabilities: [.fido2]),
            ) { context in
                try await ensurePinSet(context)
                let session = try await context.ctap2Session()

                guard try await CTAP2.Extension.MinPinLength.isSupported(by: session) else {
                    try context.skip("minPinLength not supported")
                }
                guard try await CTAP2.Config.isSupported(by: session) else {
                    try context.skip("authenticatorConfig not supported")
                }

                let info = try await session.getInfo()
                guard info.options.clientPin == true else {
                    try context.skip("PIN not set")
                }

                // Configure the RP ID to receive minPinLength (requires a direct CTAP config call).
                let configToken = try await session.getPinUVToken(
                    using: .pin(defaultTestPin),
                    permissions: [.authenticatorConfig]
                )
                let config = try await session.config(token: configToken)
                try await config.setMinPINLength(rpIDs: [testRpId])

                let client = WebAuthn.Client(
                    session: session,
                    origin: try WebAuthn.Origin(testOrigin),
                    allowedExtensions: [.minPinLength],
                    isPublicSuffix: { _ in false }
                )

                let createOptions = WebAuthn.Registration.Options(
                    challenge: randomBytes(count: 32),
                    rp: .init(id: testRpId, name: "MinPinLength Test"),
                    user: .init(id: randomBytes(count: 32), name: "minpin@example.com", displayName: "MinPin User"),
                    residentKey: .required,
                    extensions: .init(minPinLength: true)
                )

                context.touch("Touch the key to read minPinLength")
                let createResponse = try await client.makeCredential(createOptions, authorization: .pin(defaultTestPin))
                    .value
                let length = try context.require(
                    createResponse.clientExtensionResults.minPinLength?.length,
                    "minPinLength should be returned for the configured RP"
                )

                context.expect(length >= 4, "minPinLength should be at least 4")
                if let infoMinPinLength = info.minPinLength {
                    context.expect(length == infoMinPinLength, "minPinLength should match getInfo")
                }
            }
        // MARK: - previewSign
        case .noOutputWithoutInput:
            return Scenario(
                "WebAuthn.PreviewSign.noOutputWithoutInput",
                "previewSign produces no output when no input is supplied",
                requirements: Requirements(capabilities: [.fido2])
            ) { context in
                try await ensurePinSet(context)
                let session = try await context.ctap2Session()

                guard try await CTAP2.Extension.PreviewSign.isSupported(by: session) else {
                    try context.skip("previewSign not supported")
                }
                var previewClient = WebAuthn.Client(
                    session: session,
                    origin: try WebAuthn.Origin(testOrigin),
                    allowedExtensions: [.previewSign],
                    isPublicSuffix: { _ in false }
                )

                for (index, discoverable) in [true, false].enumerated() {
                    let createOptions = WebAuthn.Registration.Options(
                        challenge: randomBytes(count: 32),
                        rp: .init(id: testRpId, name: "PreviewSign Test"),
                        user: .init(
                            id: randomBytes(count: 32),
                            name: "nopsign@example.com",
                            displayName: "No PreviewSign"
                        ),
                        residentKey: discoverable ? .required : .discouraged,
                        userVerification: .discouraged
                    )

                    context.touch("Touch the key (discoverable=\(discoverable))")
                    if index > 0 {
                        previewClient = try await context.webAuthnClientAfterNFCReconnect(
                            allowedExtensions: [.previewSign]
                        )
                    }
                    let response = try await previewClient.makeCredential(
                        createOptions,
                        authorization: .pin(defaultTestPin)
                    )
                    .value
                    context.expect(
                        response.clientExtensionResults.previewSign == nil,
                        "previewSign should be absent without input (discoverable=\(discoverable))"
                    )
                }
            }
        case .generateKey:
            return Scenario(
                "WebAuthn.PreviewSign.generateKey",
                "previewSign generateKey returns a key handle, public key, and attestation",
                requirements: Requirements(capabilities: [.fido2])
            ) { context in
                try await ensurePinSet(context)
                let session = try await context.ctap2Session()

                guard try await CTAP2.Extension.PreviewSign.isSupported(by: session) else {
                    try context.skip("previewSign not supported")
                }
                var previewClient = WebAuthn.Client(
                    session: session,
                    origin: try WebAuthn.Origin(testOrigin),
                    allowedExtensions: [.previewSign],
                    isPublicSuffix: { _ in false }
                )

                // Only .esp256SplitARKGPlaceholder is currently supported by YubiKey firmware.
                let generateKeyAlgorithms: [COSE.Algorithm] = [.esp256, .esp256SplitARKGPlaceholder, .es256]

                for (index, discoverable) in [true, false].enumerated() {
                    let createOptions = WebAuthn.Registration.Options(
                        challenge: randomBytes(count: 32),
                        rp: .init(id: testRpId, name: "PreviewSign Test"),
                        user: .init(
                            id: randomBytes(count: 32),
                            name: "psign@example.com",
                            displayName: "PreviewSign User"
                        ),
                        residentKey: discoverable ? .required : .discouraged,
                        userVerification: .discouraged,
                        extensions: .init(previewSign: .generateKey(algorithms: generateKeyAlgorithms))
                    )

                    context.touch("Touch the key to generate a key (discoverable=\(discoverable))")
                    if index > 0 {
                        previewClient = try await context.webAuthnClientAfterNFCReconnect(
                            allowedExtensions: [.previewSign]
                        )
                    }
                    let response = try await previewClient.makeCredential(
                        createOptions,
                        authorization: .pin(defaultTestPin)
                    )
                    .value

                    let generatedKey = try context.require(
                        response.clientExtensionResults.previewSign?.generatedKey,
                        "Expected previewSign generatedKey output (discoverable=\(discoverable))"
                    )
                    context.expect(!generatedKey.keyHandle.isEmpty, "keyHandle should not be empty")
                    context.expect(!generatedKey.publicKey.isEmpty, "publicKey should not be empty")
                    context.expect(!generatedKey.attestationObject.isEmpty, "attestationObject should not be empty")
                    context.expect(
                        generateKeyAlgorithms.contains(generatedKey.algorithm),
                        "Algorithm \(generatedKey.algorithm) should be one of the requested algorithms"
                    )
                }
            }
        // MARK: - thirdPartyPayment
        case .echoedFalse:
            return Scenario(
                "WebAuthn.ThirdPartyPayment.echoedFalse",
                "thirdPartyPayment echoes false when the credential isn't registered for payment",
                requirements: Requirements(capabilities: [.fido2])
            ) { context in
                try await runThirdPartyPayment(context, registerWithPayment: false, expectedEcho: false)
            }
        case .echoedTrue:
            return Scenario(
                "WebAuthn.ThirdPartyPayment.echoedTrue",
                "thirdPartyPayment echoes true when the credential is registered for payment",
                requirements: Requirements(capabilities: [.fido2])
            ) { context in
                try await runThirdPartyPayment(context, registerWithPayment: true, expectedEcho: true)
            }
        }
    }
}

// MARK: - Suite-private helpers

private let defaultTestPin = Scenario.Context.defaultTestPin

private let testOrigin = "https://example.com"
private let testRpId = "example.com"
private let testRpName = "Example RP"

private func ensurePinSet(_ context: Scenario.Context) async throws {
    let session = try await context.ctap2Session()
    if try await session.getInfo().options.clientPin != true {
        try await session.setPin(defaultTestPin)
    }
}

private func firstAssertion(
    from client: WebAuthn.Client,
    options: WebAuthn.Authentication.Options,
    _ context: Scenario.Context,
    file: String = #fileID,
    line: Int = #line
) async throws -> WebAuthn.Authentication.Response {
    let matches = try await client.getAssertion(options, authorization: .pin(defaultTestPin)).value
    return try context.require(matches.first, "expected at least one assertion", file: file, line: line)
}

private func firstAssertionAfterNFCReconnect(
    _ context: Scenario.Context,
    options: WebAuthn.Authentication.Options,
    origin: String = testOrigin,
    allowedExtensions: Set<WebAuthn.Extension.Identifier> = .standard,
    file: String = #fileID,
    line: Int = #line
) async throws -> WebAuthn.Authentication.Response {
    let client = try await context.webAuthnClientAfterNFCReconnect(
        origin: origin,
        allowedExtensions: allowedExtensions
    )
    return try await firstAssertion(from: client, options: options, context, file: file, line: line)
}

private func assertion(
    from client: WebAuthn.Client,
    options: WebAuthn.Authentication.Options,
    matching credentialId: Data,
    _ context: Scenario.Context,
    file: String = #fileID,
    line: Int = #line
) async throws -> WebAuthn.Authentication.Response {
    let matches = try await client.getAssertion(options, authorization: .pin(defaultTestPin)).value
    return try context.require(
        matches.first { $0.credentialId == credentialId },
        "expected an assertion for the created credential",
        file: file,
        line: line
    )
}

private func assertionAfterNFCReconnect(
    _ context: Scenario.Context,
    options: WebAuthn.Authentication.Options,
    matching credentialId: Data,
    origin: String = testOrigin,
    allowedExtensions: Set<WebAuthn.Extension.Identifier> = .standard,
    file: String = #fileID,
    line: Int = #line
) async throws -> WebAuthn.Authentication.Response {
    let client = try await context.webAuthnClientAfterNFCReconnect(
        origin: origin,
        allowedExtensions: allowedExtensions
    )
    return try await assertion(
        from: client,
        options: options,
        matching: credentialId,
        context,
        file: file,
        line: line
    )
}

private func credPropsClient(_ context: Scenario.Context) async throws -> WebAuthn.Client {
    try await context.webAuthnClient(allowedExtensions: [.credProps])
}

private func runThirdPartyPayment(
    _ context: Scenario.Context,
    registerWithPayment: Bool,
    expectedEcho: Bool
) async throws {
    try await ensurePinSet(context)
    let session = try await context.ctap2Session()

    guard try await CTAP2.Extension.ThirdPartyPayment.isSupported(by: session) else {
        try context.skip("thirdPartyPayment not supported")
    }
    var paymentClient = WebAuthn.Client(
        session: session,
        origin: try WebAuthn.Origin(testOrigin),
        allowedExtensions: [.thirdPartyPayment],
        isPublicSuffix: { _ in false }
    )

    for (index, discoverable) in [true, false].enumerated() {
        let createOptions = WebAuthn.Registration.Options(
            challenge: randomBytes(count: 32),
            rp: .init(id: testRpId, name: "ThirdPartyPayment Test"),
            user: .init(id: randomBytes(count: 32), name: "tpp@example.com", displayName: "TPP User"),
            residentKey: discoverable ? .required : .discouraged,
            userVerification: .discouraged,
            extensions: registerWithPayment ? .init(thirdPartyPayment: .enabled) : nil
        )

        context.touch("Touch the key to create a credential (discoverable=\(discoverable))")
        if index > 0 {
            paymentClient = try await context.webAuthnClientAfterNFCReconnect(
                allowedExtensions: [.thirdPartyPayment]
            )
        }
        let createResponse = try await paymentClient.makeCredential(
            createOptions,
            authorization: .pin(defaultTestPin)
        ).value

        let authOptions = WebAuthn.Authentication.Options(
            challenge: randomBytes(count: 32),
            rpId: testRpId,
            allowCredentials: discoverable ? [] : [.init(id: createResponse.credentialId)],
            extensions: .init(thirdPartyPayment: .enabled)
        )

        context.touch("Touch the key to authenticate (discoverable=\(discoverable))")
        paymentClient = try await context.webAuthnClientAfterNFCReconnect(allowedExtensions: [.thirdPartyPayment])
        let assertions = try await paymentClient.getAssertion(authOptions, authorization: .pin(defaultTestPin)).value
        // A discoverable request returns every resident match for the RP — earlier scenarios leave
        // residents behind on example.com, so pick ours by id instead of trusting the ordering.
        let authResponse = try context.require(
            assertions.first { $0.credentialId == createResponse.credentialId },
            "expected an assertion for the just-created credential (discoverable=\(discoverable))"
        )
        let echoedBit = authResponse.clientExtensionResults.thirdPartyPayment?.isPaymentEnabled
        context.expect(
            echoedBit == expectedEcho,
            "echoed payment bit should be \(expectedEcho) (discoverable=\(discoverable))"
        )
    }
}

private func randomBytes(count: Int) -> Data {
    var bytes = [UInt8](repeating: 0, count: count)
    let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
    precondition(status == errSecSuccess, "SecRandomCopyBytes failed: \(status)")
    return Data(bytes)
}

private func decodeBase64URL(_ string: String) -> Data? {
    var s = string.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    let remainder = s.count % 4
    if remainder > 0 { s += String(repeating: "=", count: 4 - remainder) }
    return Data(base64Encoded: s)
}

private final class Box<T>: @unchecked Sendable {
    var value: T
    init(_ value: T) { self.value = value }
}
