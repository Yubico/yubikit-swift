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

import CryptoKit
import Foundation
import YubiKit

/// CTAP2 application scenarios.
public enum CTAP2Scenario: CaseIterable {

    case getInfo
    case makeGetAllowList
    case makeGetDiscoverable
    case makeES256
    case makeEdDSA
    case makeES384
    case cancelMakeCredential
    case algorithmSignatureVerify
    case getNextAssertion
    case upFalseClearsFlag
    case setupV1
    case changePinV1
    case tokenUsingUvV1
    case complexityV1
    case retryExhaustionV1
    case setupV2
    case changePinV2
    case tokenUsingUvV2
    case complexityV2
    case retryExhaustionV2
    case emptyState
    case metadata
    case enumerate
    case delete
    case updateUserInfo
    case readOnlyPpuat
    case support
    case toggleAlwaysUv
    case enableEnterpriseAttestation
    case setForcePinChange
    case setMinPinLength
    case alwaysUvEnforced
    case decryptIdentifier
    case decryptCredStoreState
    case persistentToken
    case credStoreStateChanges
    case sensorInfo
    case enrollRenameDelete
    case makeCredentialUvToken
    case uvBlocking
    case userPresence
    case factory

    public var scenario: Scenario {
        switch self {
        // MARK: - Info
        case .getInfo:
            return Scenario(
                "CTAP2.Info.getInfo",
                "getInfo reports recognized FIDO versions and options",
                requirements: Requirements(capabilities: [.fido2])
            ) { context in
                let session = try await context.ctap2Session()
                let info = try await session.getInfo()

                let recognized = info.versions.contains { version in
                    switch version {
                    case .u2fV2, .fido2_0, .fido2_1Pre, .fido2_1: return true
                    case .unknown: return false
                    }
                }
                context.expect(recognized, "should advertise a recognized FIDO version")
                context.expect(info.options.platformDevice == false, "plat should be false")
                context.expect(info.options.residentKey == true, "rk should be true")
                context.expect(info.options.userPresence == true, "up should be true")
                context.expect(info.pinUVAuthProtocols.count >= 1, "should support a PIN/UV protocol")
            }
        // MARK: - Credentials
        case .makeGetAllowList:
            return Scenario(
                "CTAP2.Credentials.makeGetAllowList",
                "makeCredential then getAssertion (by allow-list) round-trips a signature",
                requirements: Requirements(capabilities: [.fido2])
            ) { context in
                var session = try await context.ctap2Session()
                let clientDataHash = Data(repeating: 0xCD, count: 32)

                context.touch("Touch the key to create a credential")
                let makeParameters = CTAP2.MakeCredential.Parameters(
                    clientDataHash: clientDataHash,
                    rp: WebAuthn.RelyingParty(id: "example.com", name: "Example Corp"),
                    user: WebAuthn.User(
                        id: Data(repeating: 0x02, count: 32),
                        name: "alice@example.com",
                        displayName: "Alice"
                    ),
                    pubKeyCredParams: [.es256],
                    rk: false
                )
                let credential = try await session.makeCredential(parameters: makeParameters).value
                context.expect(
                    ["packed", "none"].contains(credential.attestationObject.format),
                    "expected packed or none attestation"
                )
                let attested = try context.require(
                    credential.authenticatorData.attestedCredentialData,
                    "makeCredential must return attested credential data"
                )

                context.touch("Touch the key to authenticate")
                session = try await context.ctap2SessionAfterNFCReconnect()
                let assertParameters = CTAP2.GetAssertion.Parameters(
                    rpId: "example.com",
                    clientDataHash: Data(repeating: 0xAB, count: 32),
                    allowList: [WebAuthn.CredentialDescriptor(id: attested.credentialId)]
                )
                let assertion = try await session.getAssertion(parameters: assertParameters).value
                context.expect(assertion.authenticatorData.rpIdHash.count == 32, "rpIdHash should be 32 bytes")
                context.expect(assertion.authenticatorData.flags.contains(.userPresent), "user presence flag set")
                context.expect(assertion.signature.count > 0, "a signature should be present")
            }
        case .makeGetDiscoverable:
            return Scenario(
                "CTAP2.Credentials.makeGetDiscoverable",
                "non-resident + resident makeCredential, then getAssertion by RK discovery",
                requirements: Requirements(capabilities: [.fido2])
            ) { context in
                var session = try await context.ctap2Session()
                let clientDataHash = Data(repeating: 0xCD, count: 32)

                context.touch("Touch the key to create a non-resident credential")
                let nonRkParams = CTAP2.MakeCredential.Parameters(
                    clientDataHash: clientDataHash,
                    rp: WebAuthn.RelyingParty(id: "example.com", name: "Example Corp"),
                    user: WebAuthn.User(
                        id: Data(repeating: 0x02, count: 32),
                        name: "nonrk@example.com",
                        displayName: "Non-RK User"
                    ),
                    pubKeyCredParams: [.es256],
                    rk: false
                )
                let nonRkCredential = try await session.makeCredential(parameters: nonRkParams).value
                context.expect(
                    ["packed", "none"].contains(nonRkCredential.attestationObject.format),
                    "expected packed or none attestation"
                )
                context.expect(
                    nonRkCredential.authenticatorData.attestedCredentialData != nil,
                    "missing attested credential data"
                )

                context.touch("Touch the key to create a resident credential")
                session = try await context.ctap2SessionAfterNFCReconnect()
                let rkParams = CTAP2.MakeCredential.Parameters(
                    clientDataHash: clientDataHash,
                    rp: WebAuthn.RelyingParty(id: "example.com", name: "Example Corp"),
                    user: WebAuthn.User(
                        id: Data(repeating: 0x03, count: 32),
                        name: "rk@example.com",
                        displayName: "RK User"
                    ),
                    pubKeyCredParams: [.es256],
                    rk: true
                )
                let rkCredential = try await session.makeCredential(parameters: rkParams).value
                guard rkCredential.authenticatorData.attestedCredentialData != nil else {
                    context.record("Missing attested credential data for RK")
                    return
                }

                // No allow-list: forces resident-key discovery.
                context.touch("Touch the key to authenticate")
                session = try await context.ctap2SessionAfterNFCReconnect()
                let assertParams = CTAP2.GetAssertion.Parameters(rpId: "example.com", clientDataHash: clientDataHash)
                let assertion = try await session.getAssertion(parameters: assertParams).value
                context.expect(assertion.authenticatorData.rpIdHash.count == 32, "rpIdHash should be 32 bytes")
                context.expect(assertion.authenticatorData.flags.contains(.userPresent), "user presence flag set")
                context.expect(assertion.signature.count > 0, "a signature should be present")
                context.expect(assertion.user != nil, "user handle should be present for an RK")
            }
        case .makeES256:
            return makeCredentialAlgorithmScenario(
                "CTAP2.Credentials.makeES256",
                name: "makeCredential with ES256 returns an ES256 credential key",
                algorithm: .es256,
                userByte: 0x07,
                requirements: Requirements(capabilities: [.fido2])
            )
        case .makeEdDSA:
            return makeCredentialAlgorithmScenario(
                "CTAP2.Credentials.makeEdDSA",
                name: "makeCredential with EdDSA returns an Ed25519 credential key",
                algorithm: .edDSA,
                userByte: 0x08,
                // EdDSA (Ed25519) needs YubiKey 5.2+.
                requirements: Requirements(capabilities: [.fido2], minVersion: Version("5.2.0"))
            )
        case .makeES384:
            return makeCredentialAlgorithmScenario(
                "CTAP2.Credentials.makeES384",
                name: "makeCredential with ES384 returns an ES384 credential key",
                algorithm: .es384,
                userByte: 0x35,
                // ES384 (P-384) needs YubiKey 5.6+.
                requirements: Requirements(capabilities: [.fido2], minVersion: Version("5.6.0"))
            )
        case .cancelMakeCredential:
            return Scenario(
                "CTAP2.Credentials.cancelMakeCredential",
                "makeCredential can be cancelled while waiting for user presence",
                // Cancelling while waiting for user presence needs the CTAPHID keep-alive window, so this
                // runs only on the FIDO HID transport.
                requirements: Requirements(capabilities: [.fido2], requiresFIDOTransport: true)
            ) { context in
                let session = try await context.ctap2Session()
                let params = CTAP2.MakeCredential.Parameters(
                    clientDataHash: Data(repeating: 0xCD, count: 32),
                    rp: WebAuthn.RelyingParty(id: "example.com", name: "Example Corp"),
                    user: WebAuthn.User(
                        id: Data(repeating: 0x98, count: 32),
                        name: "cancel-test@example.com",
                        displayName: "Cancel Test User"
                    ),
                    pubKeyCredParams: [.es256],
                    rk: true
                )

                context.touch("DO NOT touch the key — the operation will be cancelled")
                do {
                    for try await status in await session.makeCredential(parameters: params) {
                        switch status {
                        case .processing:
                            context.log("Processing...")
                        case .waitingForUser(let cancel):
                            context.log("Waiting for user — cancelling now")
                            await cancel()
                        case .finished(let response):
                            context.record(
                                "makeCredential should have been cancelled but got: \(String(describing: response))"
                            )
                        }
                    }
                    context.record("makeCredential should have thrown a cancellation error")
                } catch let error as CTAP2.SessionError {
                    guard case .ctapError(.keepaliveCancel, _) = error else {
                        context.record("Expected keepaliveCancel error, got: \(error)")
                        return
                    }
                    context.log("Cancellation successful — received keepaliveCancel error")
                }

                // Connection must still be usable after a cancel.
                let info = try await session.getInfo()
                context.expect(!info.versions.isEmpty, "connection should still be functional")
            }
        case .algorithmSignatureVerify:
            return Scenario(
                "CTAP2.Credentials.algorithmSignatureVerify",
                "EdDSA and ES384 assertions verify against the returned credential public key",
                // EdDSA needs YubiKey 5.2+, ES384 (P-384) needs 5.6+; this scenario exercises both.
                requirements: Requirements(capabilities: [.fido2], minVersion: Version("5.6.0"))
            ) { context in
                var session = try await context.ctap2Session()
                let cases: [(label: String, algorithm: COSE.Algorithm, userByte: UInt8)] = [
                    ("EdDSA", .edDSA, 0x41),
                    ("ES384", .es384, 0x42),
                ]
                for (index, testCase) in cases.enumerated() {
                    let rpId = "\(testCase.label.lowercased()).example"

                    context.touch("Touch the key to create the \(testCase.label) credential")
                    if index > 0 {
                        session = try await context.ctap2SessionAfterNFCReconnect()
                    }
                    let makeParameters = CTAP2.MakeCredential.Parameters(
                        clientDataHash: Data(repeating: 0xCD, count: 32),
                        rp: WebAuthn.RelyingParty(id: rpId, name: testCase.label),
                        user: WebAuthn.User(
                            id: Data(repeating: testCase.userByte, count: 32),
                            name: "\(testCase.label)@example.com",
                            displayName: testCase.label
                        ),
                        pubKeyCredParams: [testCase.algorithm],
                        rk: true
                    )
                    let credential = try await session.makeCredential(parameters: makeParameters).value
                    let attested = try context.require(
                        credential.authenticatorData.attestedCredentialData,
                        "\(testCase.label): makeCredential must return attested credential data"
                    )
                    context.expect(
                        attested.credentialPublicKey.algorithm == testCase.algorithm,
                        "\(testCase.label): credential public key should use the requested algorithm"
                    )

                    let clientDataHash = Data(repeating: 0xAB, count: 32)
                    context.touch("Touch the key to authenticate (\(testCase.label))")
                    session = try await context.ctap2SessionAfterNFCReconnect()
                    let assertParameters = CTAP2.GetAssertion.Parameters(
                        rpId: rpId,
                        clientDataHash: clientDataHash,
                        allowList: [WebAuthn.CredentialDescriptor(id: attested.credentialId)]
                    )
                    let assertion = try await session.getAssertion(parameters: assertParameters).value
                    verifyAssertionSignature(
                        context,
                        publicKey: attested.credentialPublicKey,
                        signedData: assertion.authenticatorData.rawData + clientDataHash,
                        signature: assertion.signature,
                        label: testCase.label
                    )
                }
            }
        case .getNextAssertion:
            return Scenario(
                "CTAP2.Credentials.getNextAssertion",
                "two resident credentials for one RP yield multiple assertions via getNextAssertion",
                // getNextAssertion is available on YubiKey 5.0+.
                requirements: Requirements(capabilities: [.fido2], minVersion: Version("5.0.0"))
            ) { context in
                var session = try await context.ctap2Session()
                let rpId = "getnext.example"
                let rp = WebAuthn.RelyingParty(id: rpId, name: "Get Next")
                let clientDataHash = Data(repeating: 0xCD, count: 32)
                for (index, userByte) in [UInt8(0x51), UInt8(0x52)].enumerated() {
                    context.touch("Touch the key to create resident credential \(index + 1)")
                    if index > 0 {
                        session = try await context.ctap2SessionAfterNFCReconnect()
                    }
                    let params = CTAP2.MakeCredential.Parameters(
                        clientDataHash: clientDataHash,
                        rp: rp,
                        user: WebAuthn.User(
                            id: Data(repeating: userByte, count: 32),
                            name: "user\(index + 1)@getnext.example",
                            displayName: "User \(index + 1)"
                        ),
                        pubKeyCredParams: [.es256],
                        rk: true
                    )
                    _ = try await session.makeCredential(parameters: params).value
                }

                // No allow-list forces resident-key discovery; the sequence walks getAssertion +
                // getNextAssertion, which the authenticator gates behind a single user-presence check.
                context.touch("Touch the key to authenticate")
                session = try await context.ctap2SessionAfterNFCReconnect()
                let assertParameters = CTAP2.GetAssertion.Parameters(
                    rpId: rpId,
                    clientDataHash: Data(repeating: 0xAB, count: 32)
                )
                var count = 0
                for try await assertion in await session.getAssertions(parameters: assertParameters) {
                    context.expect(assertion.signature.count > 0, "each assertion should carry a signature")
                    count += 1
                }
                context.expect(count >= 2, "expected at least two assertions for the RP, got \(count)")
            }
        case .upFalseClearsFlag:
            return Scenario(
                "CTAP2.Credentials.upFalseClearsFlag",
                "getAssertion with up=false clears the user-presence flag",
                requirements: Requirements(capabilities: [.fido2])
            ) { context in
                let session = try await context.ctap2Session()
                let rpId = "up.example"

                context.touch("Touch the key to create a credential")
                let makeParameters = CTAP2.MakeCredential.Parameters(
                    clientDataHash: Data(repeating: 0xCD, count: 32),
                    rp: WebAuthn.RelyingParty(id: rpId, name: "UP Test"),
                    user: WebAuthn.User(
                        id: Data(repeating: 0x55, count: 32),
                        name: "up@up.example",
                        displayName: "UP User"
                    ),
                    pubKeyCredParams: [.es256],
                    rk: false
                )
                let credential = try await session.makeCredential(parameters: makeParameters).value
                let attested = try context.require(
                    credential.authenticatorData.attestedCredentialData,
                    "makeCredential must return attested credential data"
                )

                // up=false suppresses the user-presence check, so the assertion's UP flag must be clear.
                let assertParameters = CTAP2.GetAssertion.Parameters(
                    rpId: rpId,
                    clientDataHash: Data(repeating: 0xAB, count: 32),
                    allowList: [WebAuthn.CredentialDescriptor(id: attested.credentialId)],
                    up: false
                )
                let assertion = try await session.getAssertion(parameters: assertParameters).value
                context.expect(
                    !assertion.authenticatorData.flags.contains(.userPresent),
                    "UP flag must be clear when up=false"
                )
            }
        case .setupV1: return Self.clientPinSetup(.v1)
        case .changePinV1: return Self.clientPinChangePin(.v1)
        case .tokenUsingUvV1: return Self.clientPinTokenUsingUv(.v1)
        case .complexityV1: return Self.clientPinComplexity(.v1)
        case .retryExhaustionV1: return Self.clientPinRetryExhaustion(.v1)
        case .setupV2: return Self.clientPinSetup(.v2)
        case .changePinV2: return Self.clientPinChangePin(.v2)
        case .tokenUsingUvV2: return Self.clientPinTokenUsingUv(.v2)
        case .complexityV2: return Self.clientPinComplexity(.v2)
        case .retryExhaustionV2: return Self.clientPinRetryExhaustion(.v2)
        // MARK: - Credential Management
        case .emptyState:
            return Scenario(
                "CTAP2.CredentialManagement.emptyState",
                "operations return empty results when no credentials exist",
                requirements: Requirements(capabilities: [.fido2])
            ) { context in
                let session = try await sessionWithPin(context)
                guard try await CTAP2.CredentialManagement.isSupported(by: session) else {
                    try context.skip("Credential management not supported")
                }
                try await deleteAllCredentials(session)

                let credMgmt = try await getCredentialManagement(session)
                let metadata = try await credMgmt.getMetadata()
                context.expectEqual(metadata.existingCredentialsCount, 0)
                context.expect(metadata.maxRemainingCredentialsCount > 0)
                let rps = try await credMgmt.rps.enumerate()
                context.expect(rps.isEmpty)
            }
        case .metadata:
            return Scenario(
                "CTAP2.CredentialManagement.metadata",
                "getMetadata reports one stored credential",
                requirements: Requirements(capabilities: [.fido2])
            ) { context in
                let session = try await sessionWithPin(context)
                guard try await CTAP2.CredentialManagement.isSupported(by: session) else {
                    try context.skip("Credential management not supported")
                }
                try await deleteAllCredentials(session)
                try await createTestCredential(session, context)

                let credMgmt = try await getCredentialManagement(session)
                let metadata = try await credMgmt.getMetadata()
                context.expectEqual(metadata.existingCredentialsCount, 1)
                context.expect(metadata.maxRemainingCredentialsCount > 0)

                try await deleteAllCredentials(session)
            }
        case .enumerate:
            return Scenario(
                "CTAP2.CredentialManagement.enumerate",
                "enumerate RPs and their credentials",
                requirements: Requirements(capabilities: [.fido2])
            ) { context in
                let session = try await sessionWithPin(context)
                guard try await CTAP2.CredentialManagement.isSupported(by: session) else {
                    try context.skip("Credential management not supported")
                }
                try await deleteAllCredentials(session)
                try await createTestCredential(session, context)

                let credMgmt = try await getCredentialManagement(session)
                var rpCount = 0
                var rpIdHash: Data?
                for try await rp in credMgmt.rps {
                    context.expect(rp.rp.id == cmTestRpId, "RP id should match")
                    context.expect(rp.rpIdHash.count == 32, "RP id hash should be 32 bytes")
                    rpIdHash = rp.rpIdHash
                    rpCount += 1
                }
                context.expectEqual(rpCount, 1)

                let hash = try context.require(rpIdHash, "expected an RP id hash")
                var credCount = 0
                for try await cred in credMgmt.credentials(for: hash) {
                    context.expect(cred.user.id == cmTestUserId, "user id should match")
                    context.expect(cred.user.name == cmTestUserName, "user name should match")
                    context.expect(cred.user.displayName == cmTestUserDisplayName, "display name should match")
                    context.expect(cred.credentialId.id.count > 0, "credential id should be present")
                    credCount += 1
                }
                context.expectEqual(credCount, 1)

                try await deleteAllCredentials(session)
            }
        case .delete:
            return Scenario(
                "CTAP2.CredentialManagement.delete",
                "delete a credential",
                requirements: Requirements(capabilities: [.fido2])
            ) { context in
                let session = try await sessionWithPin(context)
                guard try await CTAP2.CredentialManagement.isSupported(by: session) else {
                    try context.skip("Credential management not supported")
                }
                try await deleteAllCredentials(session)
                try await createTestCredential(session, context)

                let credMgmt = try await getCredentialManagement(session)
                var metadata = try await credMgmt.getMetadata()
                context.expectEqual(metadata.existingCredentialsCount, 1)

                let rps = try await credMgmt.rps.enumerate()
                let credentials = try await credMgmt.credentials(for: rps[0].rpIdHash).enumerate()
                try await credMgmt.deleteCredential(credentials[0].credentialId)

                metadata = try await credMgmt.getMetadata()
                context.expectEqual(metadata.existingCredentialsCount, 0)
            }
        case .updateUserInfo:
            return Scenario(
                "CTAP2.CredentialManagement.updateUserInfo",
                "update the user information on a credential",
                requirements: Requirements(capabilities: [.fido2])
            ) { context in
                let session = try await sessionWithPin(context)
                guard try await CTAP2.CredentialManagement.isSupported(by: session) else {
                    try context.skip("Credential management not supported")
                }
                try await deleteAllCredentials(session)
                try await createTestCredential(session, context)

                guard try await CTAP2.CredentialManagement.isUpdateSupported(by: session) else {
                    try await deleteAllCredentials(session)
                    try context.skip("Update user information not supported")
                }

                let credMgmt = try await getCredentialManagement(session)
                let rps = try await credMgmt.rps.enumerate()
                let credentials = try await credMgmt.credentials(for: rps[0].rpIdHash).enumerate()
                let credentialId = credentials[0].credentialId

                let updatedUser = WebAuthn.User(
                    id: cmTestUserId,
                    name: "UPDATED NAME",
                    displayName: "UPDATED DISPLAY NAME"
                )
                try await credMgmt.updateUserInformation(credentialId: credentialId, user: updatedUser)

                let rpsAfter = try await credMgmt.rps.enumerate()
                let updated = try await credMgmt.credentials(for: rpsAfter[0].rpIdHash).enumerate()
                context.expect(updated[0].user.id == cmTestUserId, "user id should be unchanged")
                context.expect(updated[0].user.name == "UPDATED NAME", "user name should be updated")
                context.expect(updated[0].user.displayName == "UPDATED DISPLAY NAME", "display name should be updated")

                try await deleteAllCredentials(session)
            }
        case .readOnlyPpuat:
            return Scenario(
                "CTAP2.CredentialManagement.readOnlyPpuat",
                "read-only credential management with a persistent pinUvAuthToken",
                requirements: Requirements(capabilities: [.fido2])
            ) { context in
                let session = try await sessionWithPin(context)
                guard try await CTAP2.CredentialManagement.isSupported(by: session) else {
                    try context.skip("Credential management not supported")
                }
                guard try await CTAP2.CredentialManagement.isReadOnlySupported(by: session) else {
                    try context.skip("Persistent pinUvAuthToken (read-only) not supported")
                }
                try await deleteAllCredentials(session)
                try await createTestCredential(session, context)

                let setupCredMgmt = try await getCredentialManagement(session)
                let rps = try await setupCredMgmt.rps.enumerate()
                let credentials = try await setupCredMgmt.credentials(for: rps[0].rpIdHash).enumerate()
                let credentialId = credentials[0].credentialId
                let rpIdHash = rps[0].rpIdHash

                let ppuat = try await session.getPinUVToken(
                    using: .pin(defaultTestPin),
                    permissions: [.persistentCredentialManagement]
                )
                let info = try await session.getInfo()
                let identifier = try info.encIdentifier.map { try $0.decrypted(using: ppuat) }
                let credStoreState = try info.encCredStoreState.map { try $0.decrypted(using: ppuat) }

                // Read-only ops work, write ops fail with pinAuthInvalid — before and after re-establishing.
                try await verifyReadOnlyOperations(session: session, ppuat: ppuat, rpIdHash: rpIdHash, context: context)

                let session2 = try await context.ctap2SessionAfterNFCReconnect()
                try await verifyReadOnlyOperations(
                    session: session2,
                    ppuat: ppuat,
                    rpIdHash: rpIdHash,
                    context: context
                )

                let info2 = try await session2.getInfo()
                if let identifier {
                    let identifier2 = try info2.encIdentifier!.decrypted(using: ppuat)
                    context.expectEqual(identifier2, identifier, "encIdentifier consistent across re-establishment")
                }
                if let credStoreState {
                    let credStoreState2 = try info2.encCredStoreState!.decrypted(using: ppuat)
                    context.expectEqual(
                        credStoreState2,
                        credStoreState,
                        "credStoreState consistent across re-establishment"
                    )
                }

                // Deleting a credential must change credStoreState.
                let cleanupCredMgmt = try await getCredentialManagement(session2)
                try await cleanupCredMgmt.deleteCredential(credentialId)
                if let credStoreState {
                    let info3 = try await session2.getInfo()
                    let newState = try info3.encCredStoreState!.decrypted(using: ppuat)
                    context.expect(newState != credStoreState, "credStoreState should change after a delete")
                }
            }
        // MARK: - Config (authenticatorConfig)
        case .support:
            return Scenario(
                "CTAP2.Config.support",
                "authenticatorConfig support check",
                requirements: Requirements(capabilities: [.fido2])
            ) { context in
                let session = try await sessionWithPin(context)
                let token = try await session.getPinUVToken(
                    using: .pin(defaultTestPin),
                    permissions: [.authenticatorConfig]
                )
                do {
                    _ = try await session.config(token: token)
                    context.log("authenticatorConfig is supported")
                } catch CTAP2.SessionError.featureNotSupported {
                    context.log("authenticatorConfig is not supported by this authenticator")
                }
            }
        case .toggleAlwaysUv:
            return Scenario(
                "CTAP2.Config.toggleAlwaysUv",
                "toggle the alwaysUV setting and restore it",
                requirements: Requirements(capabilities: [.fido2])
            ) { context in
                let session = try await sessionWithPin(context)
                let info = try await session.getInfo()
                guard info.options.authenticatorConfig == true else {
                    try context.skip("authenticatorConfig not supported")
                }
                guard info.options.supportsAlwaysUV else {
                    try context.skip("alwaysUV option not supported")
                }
                let initialAlwaysUV = info.options.alwaysUV ?? false

                let token = try await session.getPinUVToken(
                    using: .pin(defaultTestPin),
                    permissions: [.authenticatorConfig]
                )
                let config = try await session.config(token: token)
                try await config.toggleAlwaysUV()
                // Restore even if the body aborts below — a stuck alwaysUV forces UV on every later
                // FIDO scenario. No-op when the body's own restore already ran.
                await context.addTeardown {
                    let current = (try? await session.getInfo())?.options.alwaysUV ?? initialAlwaysUV
                    if current != initialAlwaysUV { try? await config.toggleAlwaysUV() }
                }

                let newAlwaysUV = (try await session.getInfo()).options.alwaysUV ?? false
                context.expect(newAlwaysUV != initialAlwaysUV, "alwaysUV should have toggled")

                try await config.toggleAlwaysUV()
                let restoredAlwaysUV = (try await session.getInfo()).options.alwaysUV ?? false
                context.expect(restoredAlwaysUV == initialAlwaysUV, "alwaysUV should be restored")
            }
        case .enableEnterpriseAttestation:
            return Scenario(
                "CTAP2.Config.enableEnterpriseAttestation",
                "enable enterprise attestation",
                requirements: Requirements(capabilities: [.fido2]),
            ) { context in
                let session = try await sessionWithPin(context)
                let info = try await session.getInfo()
                guard info.options.authenticatorConfig == true else {
                    try context.skip("authenticatorConfig not supported")
                }
                guard info.options.supportsEnterpriseAttestation else {
                    try context.skip("Enterprise attestation not supported")
                }

                let token = try await session.getPinUVToken(
                    using: .pin(defaultTestPin),
                    permissions: [.authenticatorConfig]
                )
                try await session.config(token: token).enableEnterpriseAttestation()
                let newInfo = try await session.getInfo()
                context.expect(
                    newInfo.options.enterpriseAttestation == true,
                    "enterprise attestation should be enabled"
                )
            }
        case .setForcePinChange:
            return Scenario(
                "CTAP2.Config.setForcePinChange",
                "set the force-PIN-change flag",
                requirements: Requirements(capabilities: [.fido2]),
                // Sticky: a PIN change or reset is required to clear the flag.
            ) { context in
                let session = try await sessionWithPin(context)
                let info = try await session.getInfo()
                guard info.options.authenticatorConfig == true else {
                    try context.skip("authenticatorConfig not supported")
                }
                guard info.forcePinChange != true else {
                    try context.skip("Force PIN change already set")
                }

                let token = try await session.getPinUVToken(
                    using: .pin(defaultTestPin),
                    permissions: [.authenticatorConfig]
                )
                try await session.config(token: token).setMinPINLength(forceChangePin: true)
                let newInfo = try await session.getInfo()
                context.expect(newInfo.forcePinChange == true, "force PIN change should be set")
            }
        case .setMinPinLength:
            return Scenario(
                "CTAP2.Config.setMinPinLength",
                "increase the minimum PIN length and reject a decrease",
                requirements: Requirements(capabilities: [.fido2]),
                // minPinLength can only increase; only a reset restores it.
            ) { context in
                let session = try await sessionWithPin(context)
                let info = try await session.getInfo()
                guard info.options.authenticatorConfig == true else {
                    try context.skip("authenticatorConfig not supported")
                }
                guard let currentMinPinLength = info.minPinLength else {
                    try context.skip("minPinLength not reported")
                }
                guard let maxPinLength = info.maxPINLength else {
                    try context.skip("maxPINLength not reported")
                }
                let newMinPinLength = currentMinPinLength + 1
                guard newMinPinLength <= maxPinLength else {
                    try context.skip("cannot increase minPinLength (\(currentMinPinLength) near max \(maxPinLength))")
                }

                let token = try await session.getPinUVToken(
                    using: .pin(defaultTestPin),
                    permissions: [.authenticatorConfig]
                )
                let config = try await session.config(token: token)
                try await config.setMinPINLength(newMinPINLength: newMinPinLength)

                let newInfo = try await session.getInfo()
                context.expect(newInfo.minPinLength == newMinPinLength, "minPinLength should have increased")

                // minPinLength must not be allowed to decrease.
                do {
                    try await config.setMinPINLength(newMinPINLength: currentMinPinLength)
                    context.record("should not be able to decrease minPinLength")
                } catch is CTAP2.SessionError {
                    context.log("decreasing minPinLength correctly rejected")
                }
            }
        case .alwaysUvEnforced:
            return Scenario(
                "CTAP2.Config.alwaysUvEnforced",
                "with alwaysUV enabled, makeCredential without UV is rejected and with UV succeeds",
                requirements: Requirements(capabilities: [.fido2])
            ) { context in
                let session = try await sessionWithPin(context)
                let info = try await session.getInfo()
                guard info.options.authenticatorConfig == true else {
                    try context.skip("authenticatorConfig not supported")
                }
                guard info.options.supportsAlwaysUV else {
                    try context.skip("alwaysUV option not supported")
                }
                let initialAlwaysUV = info.options.alwaysUV ?? false
                guard initialAlwaysUV == false else {
                    try context.skip("alwaysUV already enabled")
                }

                let token = try await session.getPinUVToken(
                    using: .pin(defaultTestPin),
                    permissions: [.authenticatorConfig]
                )
                try await session.config(token: token).toggleAlwaysUV()
                // Restore even if the body aborts below — a stuck alwaysUV forces UV on every later FIDO scenario.
                await context.addTeardown {
                    let current = (try? await session.getInfo())?.options.alwaysUV ?? initialAlwaysUV
                    guard current != initialAlwaysUV,
                        let restoreToken = try? await session.getPinUVToken(
                            using: .pin(defaultTestPin),
                            permissions: [.authenticatorConfig]
                        ),
                        let restoreConfig = try? await session.config(token: restoreToken)
                    else { return }
                    try? await restoreConfig.toggleAlwaysUV()
                }
                context.expect((try await session.getInfo()).options.alwaysUV == true, "alwaysUV should be enabled")

                let rpId = "auv.example"
                let makeParameters = CTAP2.MakeCredential.Parameters(
                    clientDataHash: Data(repeating: 0xCD, count: 32),
                    rp: WebAuthn.RelyingParty(id: rpId, name: "Always UV"),
                    user: WebAuthn.User(
                        id: Data(repeating: 0x61, count: 32),
                        name: "auv@auv.example",
                        displayName: "AUV User"
                    ),
                    pubKeyCredParams: [.es256],
                    rk: false
                )

                // Without UV, makeCredential must be rejected with PUAT_REQUIRED under alwaysUV.
                do {
                    _ = try await session.makeCredential(parameters: makeParameters).value
                    context.record("makeCredential without UV should have been rejected under alwaysUV")
                } catch let error as CTAP2.SessionError {
                    guard case .ctapError(.puatRequired, _) = error else {
                        context.record("Expected PUAT_REQUIRED, got: \(error)")
                        return
                    }
                    context.log("makeCredential without UV correctly rejected with PUAT_REQUIRED")
                }

                // The same makeCredential authorized with a PIN/UV token must still succeed and set the UV flag.
                let makeToken = try await session.getPinUVToken(
                    using: .pin(defaultTestPin),
                    permissions: [.makeCredential],
                    rpId: rpId
                )
                context.touch("Touch the key to create the credential (with UV)")
                let credential = try await session.makeCredential(parameters: makeParameters, token: makeToken).value
                context.expect(
                    credential.authenticatorData.flags.contains(.userVerified),
                    "UV flag should be set when authorized with a token under alwaysUV"
                )

                // Restore alwaysUV to its initial state.
                let restoreToken = try await session.getPinUVToken(
                    using: .pin(defaultTestPin),
                    permissions: [.authenticatorConfig]
                )
                try await session.config(token: restoreToken).toggleAlwaysUV()
                context.expect(
                    (try await session.getInfo()).options.alwaysUV == initialAlwaysUV,
                    "alwaysUV should be restored"
                )
            }
        // MARK: - Encrypted GetInfo fields
        case .decryptIdentifier:
            return Scenario(
                "CTAP2.EncryptedFields.decryptIdentifier",
                "decrypt encIdentifier with a persistent pinUvAuthToken",
                requirements: Requirements(capabilities: [.fido2])
            ) { context in
                let session = try await sessionWithPin(context)
                let info = try await session.getInfo()
                guard let encIdentifier = info.encIdentifier else {
                    try context.skip("encIdentifier not supported")
                }

                let ppuat = try await session.getPinUVToken(
                    using: .pin(defaultTestPin),
                    permissions: [.persistentCredentialManagement]
                )
                let identifier = try encIdentifier.decrypted(using: ppuat)

                let identifier2 = try (try await session.getInfo()).encIdentifier!.decrypted(using: ppuat)
                context.expectEqual(identifier, identifier2, "decrypted identifier consistent across GetInfo calls")
            }
        case .decryptCredStoreState:
            return Scenario(
                "CTAP2.EncryptedFields.decryptCredStoreState",
                "decrypt encCredStoreState with a persistent pinUvAuthToken",
                requirements: Requirements(capabilities: [.fido2])
            ) { context in
                let session = try await sessionWithPin(context)
                let info = try await session.getInfo()
                guard let encCredStoreState = info.encCredStoreState else {
                    try context.skip("encCredStoreState not supported")
                }

                let ppuat = try await session.getPinUVToken(
                    using: .pin(defaultTestPin),
                    permissions: [.persistentCredentialManagement]
                )
                let state = try encCredStoreState.decrypted(using: ppuat)

                let state2 = try (try await session.getInfo()).encCredStoreState!.decrypted(using: ppuat)
                context.expectEqual(state, state2, "decrypted state consistent when no credentials changed")
            }
        case .persistentToken:
            return Scenario(
                "CTAP2.EncryptedFields.persistentToken",
                "a persistent pinUvAuthToken decrypts the same values across re-establishment",
                requirements: Requirements(capabilities: [.fido2])
            ) { context in
                let session = try await sessionWithPin(context)
                let info = try await session.getInfo()
                guard let encIdentifier = info.encIdentifier else {
                    try context.skip("encIdentifier not supported")
                }

                let ppuat = try await session.getPinUVToken(
                    using: .pin(defaultTestPin),
                    permissions: [.persistentCredentialManagement]
                )
                let identifier1 = try encIdentifier.decrypted(using: ppuat)
                let credStoreState1 = try info.encCredStoreState.map { try $0.decrypted(using: ppuat) }

                let session2 = try await context.ctap2SessionAfterNFCReconnect()
                let info2 = try await session2.getInfo()
                let identifier2 = try info2.encIdentifier!.decrypted(using: ppuat)
                context.expectEqual(identifier1, identifier2, "device identifier consistent across re-establishment")

                if let credStoreState1 {
                    let credStoreState2 = try info2.encCredStoreState!.decrypted(using: ppuat)
                    context.expectEqual(
                        credStoreState1,
                        credStoreState2,
                        "credStoreState consistent across re-establishment"
                    )
                }
            }
        case .credStoreStateChanges:
            return Scenario(
                "CTAP2.EncryptedFields.credStoreStateChanges",
                "credStoreState changes when credentials are added or deleted",
                requirements: Requirements(capabilities: [.fido2])
            ) { context in
                let session = try await sessionWithPin(context)
                let info = try await session.getInfo()
                guard info.encCredStoreState != nil else {
                    try context.skip("encCredStoreState not supported")
                }
                guard try await CTAP2.CredentialManagement.isSupported(by: session) else {
                    try context.skip("Credential management not supported")
                }
                guard try await CTAP2.CredentialManagement.isReadOnlySupported(by: session) else {
                    try context.skip("Persistent pinUvAuthToken (read-only) not supported")
                }

                let ppuat = try await session.getPinUVToken(
                    using: .pin(defaultTestPin),
                    permissions: [.persistentCredentialManagement]
                )

                let cmToken = try await session.getPinUVToken(
                    using: .pin(defaultTestPin),
                    permissions: [.credentialManagement]
                )
                let credMgmt = try await session.credentialManagement(token: cmToken)
                for try await rp in credMgmt.rps {
                    for try await cred in credMgmt.credentials(for: rp.rpIdHash) {
                        try await credMgmt.deleteCredential(cred.credentialId)
                    }
                }

                let state1 = try (try await session.getInfo()).encCredStoreState!.decrypted(using: ppuat)

                let makeCredToken = try await session.getPinUVToken(
                    using: .pin(defaultTestPin),
                    permissions: [.makeCredential],
                    rpId: cmTestRpId
                )
                let params = CTAP2.MakeCredential.Parameters(
                    clientDataHash: cmClientDataHash,
                    rp: cmTestRp,
                    user: WebAuthn.User(id: Data([0x01, 0x02, 0x03]), name: "test", displayName: "Test"),
                    pubKeyCredParams: [.es256],
                    rk: true
                )
                context.touch("Touch the key to create a credential")
                _ = try await session.makeCredential(parameters: params, token: makeCredToken).value

                let state2 = try (try await session.getInfo()).encCredStoreState!.decrypted(using: ppuat)
                context.expect(state2 != state1, "credStoreState should change after credential creation")

                let deleteToken = try await session.getPinUVToken(
                    using: .pin(defaultTestPin),
                    permissions: [.credentialManagement]
                )
                let credMgmt2 = try await session.credentialManagement(token: deleteToken)
                let rps = try await credMgmt2.rps.enumerate()
                let creds = try await credMgmt2.credentials(for: rps[0].rpIdHash).enumerate()
                try await credMgmt2.deleteCredential(creds[0].credentialId)

                let state3 = try (try await session.getInfo()).encCredStoreState!.decrypted(using: ppuat)
                context.expect(state3 != state2, "credStoreState should change after credential deletion")
            }
        // MARK: - Bio (fingerprint)
        case .sensorInfo:
            return Scenario(
                "CTAP2.Bio.sensorInfo",
                "read the fingerprint sensor info",
                requirements: Requirements(capabilities: [.fido2], requiresBio: true)
            ) { context in
                let (_, bio) = try await bioEnrollmentSession(context)
                let info = try await bio.getFingerprintSensorInfo()
                context.expect(
                    [.touch, .swipe].contains(info.fingerprintKind),
                    "fingerprintKind should be touch or swipe"
                )
                context.expect(info.maxCaptureSamplesRequired > 0, "maxCaptureSamplesRequired should be > 0")
                if let maxName = info.maxTemplateFriendlyName {
                    context.expect(maxName > 0, "maxTemplateFriendlyName should be > 0 when present")
                }
            }
        case .enrollRenameDelete:
            return Scenario(
                "CTAP2.Bio.enrollRenameDelete",
                "enroll, rename, and delete a fingerprint",
                requirements: Requirements(capabilities: [.fido2], requiresBio: true)
            ) { context in
                let (_, bio) = try await bioEnrollmentSession(context)
                let templateId = try await enrollOneFingerprint(bio, context)

                var enrollments = try await bio.enrollments.enumerate()
                context.expectEqual(enrollments.count, 1)
                context.expect(enrollments[0].templateId == templateId, "enrolled template id should match")
                context.expect(
                    enrollments[0].friendlyName == nil || enrollments[0].friendlyName == "",
                    "a fresh enrollment should have no friendly name"
                )

                try await bio.setFriendlyName("Test 1", for: templateId)
                enrollments = try await bio.enrollments.enumerate()
                context.expectEqual(enrollments.count, 1)
                context.expect(enrollments[0].friendlyName == "Test 1", "friendly name should be set")

                let sensorInfo = try await bio.getFingerprintSensorInfo()
                if let maxLen = sensorInfo.maxTemplateFriendlyName {
                    let maxName = "Test" + String(repeating: "!", count: Int(maxLen) - 4)
                    try await bio.setFriendlyName(maxName, for: templateId)
                    enrollments = try await bio.enrollments.enumerate()
                    context.expectEqual(enrollments.count, 1)
                    context.expect(enrollments[0].friendlyName == maxName, "max-length friendly name should be set")

                    let tooLongName = "Test" + String(repeating: "!", count: Int(maxLen) - 3)
                    do {
                        try await bio.setFriendlyName(tooLongName, for: templateId)
                        context.record("a name exceeding the max length should be rejected")
                    } catch let error as CTAP2.SessionError {
                        guard case .ctapError(.invalidLength, _) = error else {
                            context.record("Expected invalidLength, got: \(error)")
                            return
                        }
                        context.log("over-length name correctly rejected with invalidLength")
                    }
                }

                try await bio.removeEnrollment(templateId)
                context.expect(
                    try await bio.enrollments.enumerate().isEmpty,
                    "enrollments should be empty after delete"
                )
            }
        case .makeCredentialUvToken:
            return Scenario(
                "CTAP2.Bio.makeCredentialUvToken",
                "create a credential using a fingerprint UV token (UP + UV flags)",
                requirements: Requirements(capabilities: [.fido2], requiresBio: true)
            ) { context in
                let (session, bio) = try await bioEnrollmentSession(context)
                let templateId = try await enrollOneFingerprint(bio, context)
                // Teardown, not a trailing call: a mid-body failure must not leave the enrollment behind.
                await context.addTeardown { await cleanupEnrollment(session, templateId) }
                context.touch("Touch the enrolled fingerprint to get a UV token")
                let uvToken = try await session.getPinUVToken(
                    using: .uv,
                    permissions: [.makeCredential],
                    rpId: "example.com"
                )
                let params = CTAP2.MakeCredential.Parameters(
                    clientDataHash: Data(repeating: 0xCD, count: 32),
                    rp: WebAuthn.RelyingParty(id: "example.com", name: "Example"),
                    user: WebAuthn.User(
                        id: Data(repeating: 0x10, count: 32),
                        name: "uv-user@example.com",
                        displayName: "UV User"
                    ),
                    pubKeyCredParams: [.es256],
                    rk: true
                )
                let credential = try await session.makeCredential(parameters: params, token: uvToken).value
                context.expect(credential.authenticatorData.flags.contains(.userPresent), "UP flag should be set")
                context.expect(credential.authenticatorData.flags.contains(.userVerified), "UV flag should be set")
            }
        case .uvBlocking:
            return Scenario(
                "CTAP2.Bio.uvBlocking",
                "UV blocks after repeated wrong fingerprints, then PIN still works",
                // Presenting a *wrong* fingerprint needs an actual sensor, so this is real-hardware only.
                requirements: Requirements(capabilities: [.fido2], requiresBio: true, requiresRealHardware: true)
            ) { context in
                let (session, bio) = try await bioEnrollmentSession(context)
                let templateId = try await enrollOneFingerprint(bio, context)
                // Teardown, not a trailing call: a mid-body failure must not leave the enrollment behind.
                await context.addTeardown { await cleanupEnrollment(session, templateId) }

                let maxAttempts = 10
                context.log("Use a DIFFERENT fingerprint (not the enrolled one) until UV is blocked")
                var blocked = false
                var attempt = 0
                while attempt < maxAttempts, !blocked {
                    attempt += 1
                    do {
                        context.touch("Attempt \(attempt): touch a WRONG fingerprint")
                        _ = try await session.getPinUVToken(
                            using: .uv,
                            permissions: [.makeCredential],
                            rpId: "example.com"
                        )
                        context.record("wrong fingerprint should have been rejected")
                    } catch let error as CTAP2.SessionError {
                        if case .ctapError(let code, _) = error {
                            if code == .uvBlocked {
                                context.log("UV_BLOCKED after \(attempt) failed attempts")
                                blocked = true
                            } else {
                                context.expect(
                                    code == .uvInvalid,
                                    "Expected uvInvalid on attempt \(attempt), got: \(code)"
                                )
                            }
                        } else {
                            context.record("Expected a CTAP error, got: \(error)")
                        }
                    }
                }
                context.expect(blocked, "UV should block within \(maxAttempts) wrong attempts")

                // PIN must still work even with UV blocked.
                context.touch("Touch the sensor for user presence (PIN will be used, not UV)")
                let pinToken = try await session.getPinUVToken(
                    using: .pin(defaultTestPin),
                    permissions: [.makeCredential],
                    rpId: "example.com"
                )
                let params = CTAP2.MakeCredential.Parameters(
                    clientDataHash: Data(repeating: 0xCD, count: 32),
                    rp: WebAuthn.RelyingParty(id: "example.com", name: "Example"),
                    user: WebAuthn.User(
                        id: Data(repeating: 0x01, count: 32),
                        name: "pin-user@example.com",
                        displayName: "PIN User"
                    ),
                    pubKeyCredParams: [.es256],
                    rk: true
                )
                let credential = try await session.makeCredential(parameters: params, token: pinToken).value
                // Per CTAP 2.2 §6.1.1 a valid pinUvAuthParam sets the UV flag regardless of token type.
                context.expect(credential.authenticatorData.flags.contains(.userPresent), "UP flag should be set")
                context.expect(credential.authenticatorData.flags.contains(.userVerified), "UV flag should be set")
            }
        // MARK: - Selection
        case .userPresence:
            return Scenario(
                "CTAP2.Selection.userPresence",
                "selection performs a user-presence check",
                requirements: Requirements(capabilities: [.fido2])
            ) { context in
                let session = try await context.ctap2Session()
                context.touch("Touch the key to confirm selection")

                var receivedWaitingForUser = false
                for try await status in await session.selection() {
                    switch status {
                    case .processing: context.log("Processing...")
                    case .waitingForUser: receivedWaitingForUser = true
                    case .finished: context.log("Selection completed")
                    }
                }

                // The keep-alive surfaces a waitingForUser status on every backend; only NFC can't relay
                // SW_KEEPALIVE, so skip the assertion there.
                if context.deviceTransport != .nfc {
                    context.expect(receivedWaitingForUser, "should receive waitingForUser during selection")
                } else {
                    context.log("selection completed (waitingForUser=\(receivedWaitingForUser))")
                }
            }
        // MARK: - Reset
        case .factory:
            return Scenario(
                "CTAP2.Reset.factory",
                "factory reset clears credentials and the PIN",
                // FIDO reset needs a wired link (USB or Lightning — both report `.usb`); NFC rejects it.
                requirements: Requirements(capabilities: [.fido2], transports: [.usb]),
            ) { context in
                let session = try await context.ctap2Session()
                context.touch("Touch the key to confirm the reset")

                var receivedWaitingForUser = false
                for try await status in await session.reset() {
                    if case .waitingForUser = status { receivedWaitingForUser = true }
                }
                if context.deviceTransport != .nfc {
                    context.expect(receivedWaitingForUser, "should receive waitingForUser during reset")
                }

                let info = try await session.getInfo()
                context.expect(info.options.clientPin != true, "PIN should be cleared after a reset")
            }
        }
    }

    // MARK: - ClientPIN

    private static func clientPinSetup(_ pinProtocol: CTAP2.ClientPin.ProtocolVersion) -> Scenario {
        let isV1 = pinProtocol == .v1
        let suffix = isV1 ? "V1" : "V2"
        return Scenario(
            isV1 ? "CTAP2.ClientPIN.setupV1" : "CTAP2.ClientPIN.setupV2",
            "clientPIN setup: set the PIN and reset the retry counter (\(suffix))",
            requirements: Requirements(capabilities: [.fido2])
        ) { context in
            let session = try await context.ctap2Session()
            let info = try await session.getInfo()
            guard info.options.supportsClientPin else {
                try context.skip("Device doesn't support clientPin")
            }

            if info.options.clientPin != true {
                try await session.setPin(defaultTestPin, protocol: pinProtocol)
                context.log("PIN set to default")
            }

            // A successful PIN auth resets the retry counter.
            _ = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.makeCredential],
                rpId: "localhost",
                protocol: pinProtocol
            )
            let retries = try await session.getPinRetries(protocol: pinProtocol)
            context.expectEqual(retries.retries, 8, "should have 8 PIN retries after a successful auth")
        }
    }

    private static func clientPinChangePin(_ pinProtocol: CTAP2.ClientPin.ProtocolVersion) -> Scenario {
        let isV1 = pinProtocol == .v1
        let suffix = isV1 ? "V1" : "V2"
        return Scenario(
            isV1 ? "CTAP2.ClientPIN.changePinV1" : "CTAP2.ClientPIN.changePinV2",
            "clientPIN change PIN and verify the retry counter (\(suffix))",
            requirements: Requirements(capabilities: [.fido2])
        ) { context in
            let session = try await sessionWithPin(context)
            let otherPin = "76543211"

            _ = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.makeCredential],
                rpId: "localhost",
                protocol: pinProtocol
            )
            let initial = try await session.getPinRetries(protocol: pinProtocol)
            context.expectEqual(initial.retries, 8, "should start with 8 PIN retries")

            try await session.changePin(from: defaultTestPin, to: otherPin, protocol: pinProtocol)

            // The old PIN must now be rejected and decrement the counter.
            do {
                _ = try await session.getPinUVToken(
                    using: .pin(defaultTestPin),
                    permissions: [.makeCredential, .getAssertion],
                    rpId: "localhost",
                    protocol: pinProtocol
                )
                context.record("old PIN should have been rejected")
            } catch let error as CTAP2.SessionError {
                guard case .ctapError(.pinInvalid, _) = error else {
                    context.record("Expected PIN_INVALID, got: \(error)")
                    return
                }
                context.log("old PIN rejected")
            }
            let afterWrong = try await session.getPinRetries(protocol: pinProtocol)
            context.expectEqual(afterWrong.retries, 7, "retries should decrement after a wrong PIN")

            // The new PIN succeeds and resets the counter.
            _ = try await session.getPinUVToken(
                using: .pin(otherPin),
                permissions: [.makeCredential, .getAssertion],
                rpId: "localhost",
                protocol: pinProtocol
            )
            let afterCorrect = try await session.getPinRetries(protocol: pinProtocol)
            context.expectEqual(afterCorrect.retries, 8, "retries should reset after a correct PIN")

            try await session.changePin(from: otherPin, to: defaultTestPin, protocol: pinProtocol)
        }
    }

    private static func clientPinTokenUsingUv(_ pinProtocol: CTAP2.ClientPin.ProtocolVersion) -> Scenario {
        let isV1 = pinProtocol == .v1
        let suffix = isV1 ? "V1" : "V2"
        return Scenario(
            isV1 ? "CTAP2.ClientPIN.tokenUsingUvV1" : "CTAP2.ClientPIN.tokenUsingUvV2",
            "clientPIN get token using built-in UV (\(suffix))",
            requirements: Requirements(capabilities: [.fido2])
        ) { context in
            let session = try await sessionWithPin(context)
            let info = try await session.getInfo()

            // On a device without pinUvAuthToken, requesting a UV token must throw featureNotSupported.
            guard info.options.pinUVAuthToken == true else {
                do {
                    _ = try await session.getPinUVToken(
                        using: .uv,
                        permissions: [.makeCredential, .getAssertion],
                        rpId: "example.com",
                        protocol: pinProtocol
                    )
                    context.record("should have thrown featureNotSupported")
                } catch let error as CTAP2.SessionError {
                    guard case .featureNotSupported = error else {
                        context.record("Expected featureNotSupported, got: \(error)")
                        return
                    }
                    context.log("correctly threw featureNotSupported on a non-UV device")
                }
                return
            }

            guard info.options.userVerification == true else {
                try context.skip("UV supported but not configured (no fingerprints enrolled)")
            }

            context.touch("Touch the fingerprint sensor on the YubiKey Bio")
            let token = try await session.getPinUVToken(
                using: .uv,
                permissions: [.makeCredential, .getAssertion],
                rpId: "example.com",
                protocol: pinProtocol
            )
            context.expectEqual(token.protocolVersion, pinProtocol, "token protocol should match the request")
        }
    }

    private static func clientPinComplexity(_ pinProtocol: CTAP2.ClientPin.ProtocolVersion) -> Scenario {
        let isV1 = pinProtocol == .v1
        let suffix = isV1 ? "V1" : "V2"
        return Scenario(
            isV1 ? "CTAP2.ClientPIN.complexityV1" : "CTAP2.ClientPIN.complexityV2",
            "clientPIN complexity enforcement rejects weak PINs (\(suffix))",
            requirements: Requirements(capabilities: [.fido2])
        ) { context in
            let session = try await sessionWithPin(context)
            let info = try await session.getInfo()
            guard info.pinComplexityPolicy == true else {
                try context.skip("Device doesn't enforce PIN complexity")
            }

            do {
                try await session.changePin(from: defaultTestPin, to: "33333333", protocol: pinProtocol)
                context.record("weak PIN should have been rejected")
            } catch let error as CTAP2.SessionError {
                guard case .ctapError(.pinPolicyViolation, _) = error else {
                    context.record("Expected PIN_POLICY_VIOLATION, got: \(error)")
                    return
                }
                context.log("weak PIN correctly rejected with PIN_POLICY_VIOLATION")
            }

            // A policy violation must not decrement the retry counter.
            let retries = try await session.getPinRetries(protocol: pinProtocol)
            context.expectEqual(retries.retries, 8, "policy violations must not decrement retries")
        }
    }

    private static func clientPinRetryExhaustion(_ pinProtocol: CTAP2.ClientPin.ProtocolVersion) -> Scenario {
        let isV1 = pinProtocol == .v1
        let suffix = isV1 ? "V1" : "V2"
        return Scenario(
            isV1 ? "CTAP2.ClientPIN.retryExhaustionV1" : "CTAP2.ClientPIN.retryExhaustionV2",
            "clientPIN retry exhaustion soft-locks the authenticator (\(suffix))",
            requirements: Requirements(capabilities: [.fido2]),
        ) { context in
            let session = try await sessionWithPin(context)
            let wrongPin = "99999999"

            _ = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.makeCredential, .getAssertion],
                rpId: "localhost",
                protocol: pinProtocol
            )
            var retries = try await session.getPinRetries(protocol: pinProtocol)
            context.expectEqual(retries.retries, 8)

            // 8 -> 7 -> 6 -> 5 (the third wrong attempt may soft-lock).
            for expected in [7, 6, 5] {
                do {
                    _ = try await session.getPinUVToken(
                        using: .pin(wrongPin),
                        permissions: [.makeCredential, .getAssertion],
                        rpId: "localhost",
                        protocol: pinProtocol
                    )
                    context.record("wrong PIN should have been rejected")
                } catch let error as CTAP2.SessionError {
                    if case .ctapError(.pinInvalid, _) = error {
                        // expected
                    } else if case .ctapError(.pinAuthBlocked, _) = error {
                        // expected (soft-lock)
                    } else {
                        context.record("Expected PIN_INVALID or PIN_AUTH_BLOCKED, got: \(error)")
                    }
                }
                retries = try await session.getPinRetries(protocol: pinProtocol)
                context.expectEqual(retries.retries, expected)
            }

            // Soft-locked: the counter freezes and even the correct PIN is blocked.
            let frozen = retries.retries
            do {
                _ = try await session.getPinUVToken(
                    using: .pin(wrongPin),
                    permissions: [.makeCredential, .getAssertion],
                    rpId: "localhost",
                    protocol: pinProtocol
                )
                context.record("wrong PIN should be blocked")
            } catch let error as CTAP2.SessionError {
                guard case .ctapError(.pinAuthBlocked, _) = error else {
                    context.record("Expected PIN_AUTH_BLOCKED, got: \(error)")
                    return
                }
            }
            retries = try await session.getPinRetries(protocol: pinProtocol)
            context.expectEqual(retries.retries, frozen)

            do {
                _ = try await session.getPinUVToken(
                    using: .pin(defaultTestPin),
                    permissions: [.makeCredential, .getAssertion],
                    rpId: "localhost",
                    protocol: pinProtocol
                )
                context.record("correct PIN should be blocked while soft-locked")
            } catch let error as CTAP2.SessionError {
                guard case .ctapError(.pinAuthBlocked, _) = error else {
                    context.record("Expected PIN_AUTH_BLOCKED, got: \(error)")
                    return
                }
            }
            retries = try await session.getPinRetries(protocol: pinProtocol)
            context.expectEqual(retries.retries, frozen)
            context.log("authenticator soft-locked — power-cycle to unlock")
        }
    }
}

// MARK: - Shared constants

private let defaultTestPin = Scenario.Context.defaultTestPin

private let cmTestRpId = "test.example.com"
private let cmTestRp = WebAuthn.RelyingParty(id: cmTestRpId, name: "Test RP")
private let cmTestUserId = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
private let cmTestUserName = "testuser@example.com"
private let cmTestUserDisplayName = "Test User"
private let cmTestUser = WebAuthn.User(id: cmTestUserId, name: cmTestUserName, displayName: cmTestUserDisplayName)
private let cmClientDataHash = Data(repeating: 0xCD, count: 32)

// MARK: - Signature verification

/// Verifies an assertion signature against the credential's COSE public key.
private func verifyAssertionSignature(
    _ context: Scenario.Context,
    publicKey: COSE.Key,
    signedData: Data,
    signature: Data,
    label: String
) {
    switch publicKey {
    case let .okp(_, _, crv, x) where crv == 6:  // Ed25519
        guard let key = try? Curve25519.Signing.PublicKey(rawRepresentation: x) else {
            context.record("\(label): failed to build an Ed25519 public key")
            return
        }
        context.expect(key.isValidSignature(signature, for: signedData), "\(label): signature must verify")
    case let .ec2(_, _, crv, x, y) where crv == 2:  // P-384
        let x963 = Data([0x04]) + x + y
        guard let key = try? P384.Signing.PublicKey(x963Representation: x963),
            let ecdsaSignature = try? P384.Signing.ECDSASignature(derRepresentation: signature)
        else {
            context.record("\(label): failed to build a P-384 key or signature")
            return
        }
        context.expect(key.isValidSignature(ecdsaSignature, for: signedData), "\(label): signature must verify")
    default:
        context.record("\(label): unexpected COSE key type for signature verification")
    }
}

// MARK: - Parameterized scenario builders

private func makeCredentialAlgorithmScenario(
    _ id: String,
    name: String,
    algorithm: COSE.Algorithm,
    userByte: UInt8,
    requirements: Requirements
) -> Scenario {
    Scenario(id, name, requirements: requirements) { context in
        let session = try await context.ctap2Session()
        context.touch("Touch the key to create the credential")
        let params = CTAP2.MakeCredential.Parameters(
            clientDataHash: Data(repeating: 0xCD, count: 32),
            rp: WebAuthn.RelyingParty(id: "example.com", name: "Example Corp"),
            user: WebAuthn.User(
                id: Data(repeating: userByte, count: 32),
                name: "algo@example.com",
                displayName: "Algo User"
            ),
            pubKeyCredParams: [algorithm],
            rk: false
        )
        let credential = try await session.makeCredential(parameters: params).value
        let attested = try context.require(
            credential.authenticatorData.attestedCredentialData,
            "makeCredential must return attested credential data"
        )
        let keyAlgorithm = try context.require(
            attested.credentialPublicKey.algorithm,
            "credential public key should carry an algorithm"
        )
        context.expectEqual(keyAlgorithm, algorithm, "credential public key algorithm")
    }
}

private func sessionWithPin(_ context: Scenario.Context) async throws -> CTAP2.Session {
    let session = try await context.ctap2Session()
    let info = try await session.getInfo()
    if info.options.clientPin != true {
        try await session.setPin(defaultTestPin)
    }
    return session
}

private func getCredentialManagement(_ session: CTAP2.Session) async throws -> CTAP2.CredentialManagement {
    let token = try await session.getPinUVToken(using: .pin(defaultTestPin), permissions: [.credentialManagement])
    return try await session.credentialManagement(token: token)
}

private func createTestCredential(_ session: CTAP2.Session, _ context: Scenario.Context) async throws {
    let pinToken = try await session.getPinUVToken(
        using: .pin(defaultTestPin),
        permissions: [.makeCredential],
        rpId: cmTestRpId
    )
    let params = CTAP2.MakeCredential.Parameters(
        clientDataHash: cmClientDataHash,
        rp: cmTestRp,
        user: cmTestUser,
        pubKeyCredParams: [.es256],
        rk: true
    )
    context.touch("Touch the key to create the test credential")
    _ = try await session.makeCredential(parameters: params, token: pinToken).value
}

private func deleteAllCredentials(_ session: CTAP2.Session) async throws {
    let credMgmt = try await getCredentialManagement(session)
    for try await rp in credMgmt.rps {
        for try await credential in credMgmt.credentials(for: rp.rpIdHash) {
            try await credMgmt.deleteCredential(credential.credentialId)
        }
    }
}

/// Verifies persistent token read/write behavior.
private func verifyReadOnlyOperations(
    session: CTAP2.Session,
    ppuat: CTAP2.Token,
    rpIdHash: Data,
    context: Scenario.Context
) async throws {
    let credMgmt = try await session.credentialManagement(token: ppuat)

    let metadata = try await credMgmt.getMetadata()
    context.expectEqual(metadata.existingCredentialsCount, 1)
    let rps = try await credMgmt.rps.enumerate()
    context.expectEqual(rps.count, 1)
    let credentials = try await credMgmt.credentials(for: rpIdHash).enumerate()
    context.expectEqual(credentials.count, 1)
    let credentialId = credentials[0].credentialId

    // Writes must fail with pinAuthInvalid.
    do {
        let user = WebAuthn.User(id: Data([0x01, 0x02, 0x03]), name: "X", displayName: "X")
        try await credMgmt.updateUserInformation(credentialId: credentialId, user: user)
        context.record("updateUserInformation should fail with a persistent token")
    } catch let error {
        guard case .ctapError(.pinAuthInvalid, _) = error else {
            context.record("expected pinAuthInvalid, got: \(error)")
            throw error
        }
    }
    do {
        try await credMgmt.deleteCredential(credentialId)
        context.record("deleteCredential should fail with a persistent token")
    } catch let error {
        guard case .ctapError(.pinAuthInvalid, _) = error else {
            context.record("expected pinAuthInvalid, got: \(error)")
            throw error
        }
    }
}

// MARK: - Bio helpers

private func bioEnrollmentSession(_ context: Scenario.Context) async throws -> (CTAP2.Session, CTAP2.BioEnrollment) {
    let session = try await sessionWithPin(context)
    try context.require(await CTAP2.BioEnrollment.isSupported(by: session), "Bio enrollment not supported")
    let pinToken = try await session.getPinUVToken(using: .pin(defaultTestPin), permissions: [.bioEnrollment])
    let bio = try await session.bioEnrollment(token: pinToken)
    return (session, bio)
}

private func enrollOneFingerprint(_ bio: CTAP2.BioEnrollment, _ context: Scenario.Context) async throws -> Data {
    for template in try await bio.enrollments.enumerate() {
        try await bio.removeEnrollment(template.templateId)
    }

    var templateId: Data?
    context.touch("Touch the fingerprint sensor to enroll")
    for try await sample in bio.enroll() {
        switch sample {
        case .waitingForUser:
            context.log("Touch the sensor...")
        case .sample(let status, let remaining):
            context.log(status == .good ? "\(remaining) more scans needed" : "sample: \(status)")
        case .completed(let id, _):
            templateId = id
        }
    }
    return try context.require(templateId, "failed to enroll fingerprint")
}

private func cleanupEnrollment(_ session: CTAP2.Session, _ templateId: Data) async {
    guard let token = try? await session.getPinUVToken(using: .pin(defaultTestPin), permissions: [.bioEnrollment]),
        let bio = try? await session.bioEnrollment(token: token)
    else { return }
    try? await bio.removeEnrollment(templateId)
}
