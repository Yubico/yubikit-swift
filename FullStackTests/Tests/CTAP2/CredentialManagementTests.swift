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
import YubiKit

// MARK: - Test Constants

private let testClientDataHash = Data(repeating: 0xCD, count: 32)
private let testRpId = "test.example.com"
private let testRp = WebAuthn.RelyingParty(id: testRpId, name: "Test RP")
private let testUserId = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
private let testUserName = "testuser@example.com"
private let testUserDisplayName = "Test User"
private let testUser = WebAuthn.User(
    id: testUserId,
    name: testUserName,
    displayName: testUserDisplayName
)

// MARK: - Tests

@Suite("Credential Management", .serialized)
struct CredentialManagementTests {

    // MARK: - Empty State

    @Test("Operations return empty results when no credentials exist")
    func testEmptyState() async throws {
        try await withCredentialManagement(createCredential: false) { credMgmt, _ in
            let metadata = try await credMgmt.getMetadata()
            #expect(metadata.existingCredentialsCount == 0)
            #expect(metadata.maxRemainingCredentialsCount > 0)

            let rps = try await credMgmt.rps.enumerate()
            #expect(rps.isEmpty)
        }
    }

    // MARK: - Metadata

    @Test("Get credential metadata")
    func testMetadata() async throws {
        try await withCredentialManagement(createCredential: true) { credMgmt, _ in
            let metadata = try await credMgmt.getMetadata()
            #expect(metadata.existingCredentialsCount == 1)
            #expect(metadata.maxRemainingCredentialsCount > 0)
        }
    }

    // MARK: - Enumerate

    @Test("Enumerate RPs and credentials")
    func testEnumerate() async throws {
        try await withCredentialManagement(createCredential: true) { credMgmt, _ in
            var rpCount = 0
            var rpIdHash: Data?
            for try await rp in credMgmt.rps {
                #expect(rp.rp.id == testRpId)
                #expect(rp.rpIdHash.count == 32)
                rpIdHash = rp.rpIdHash
                rpCount += 1
            }
            #expect(rpCount == 1)

            var credCount = 0
            for try await cred in credMgmt.credentials(for: rpIdHash!) {
                #expect(cred.user.id == testUserId)
                #expect(cred.user.name == testUserName)
                #expect(cred.user.displayName == testUserDisplayName)
                #expect(cred.credentialId.id.count > 0)
                credCount += 1
            }
            #expect(credCount == 1)
        }
    }

    // MARK: - Delete

    @Test("Delete credential")
    func testDelete() async throws {
        try await withCredentialManagement(createCredential: true) { credMgmt, session in
            // Verify credential exists
            var metadata = try await credMgmt.getMetadata()
            #expect(metadata.existingCredentialsCount == 1)

            // Get and delete the credential
            let rps = try await credMgmt.rps.enumerate()
            let credentials = try await credMgmt.credentials(for: rps[0].rpIdHash).enumerate()
            try await credMgmt.deleteCredential(credentials[0].credentialId)

            // Verify deletion
            metadata = try await credMgmt.getMetadata()
            #expect(metadata.existingCredentialsCount == 0)
        }
    }

    // MARK: - Update User Information

    @Test("Update user information")
    func testUpdateUserInfo() async throws {
        try await withCredentialManagement(createCredential: true) { credMgmt, session in
            guard try await CTAP2.CredentialManagement.isUpdateSupported(by: session) else {
                print("Update user information not supported - skipping")
                return
            }

            // Get the credential
            let rps = try await credMgmt.rps.enumerate()
            let credentials = try await credMgmt.credentials(for: rps[0].rpIdHash).enumerate()
            let credentialId = credentials[0].credentialId

            // Update user info
            let updatedUser = WebAuthn.User(
                id: testUserId,
                name: "UPDATED NAME",
                displayName: "UPDATED DISPLAY NAME"
            )
            try await credMgmt.updateUserInformation(credentialId: credentialId, user: updatedUser)

            // Verify update
            let rpsAfter = try await credMgmt.rps.enumerate()
            let updated = try await credMgmt.credentials(for: rpsAfter[0].rpIdHash).enumerate()

            #expect(updated[0].user.id == testUserId)
            #expect(updated[0].user.name == "UPDATED NAME")
            #expect(updated[0].user.displayName == "UPDATED DISPLAY NAME")
        }
    }

    // MARK: - Persistent Token (PPUAT)

    @Test("Read-only management with persistent token")
    func testReadOnlyWithPPUAT() async throws {
        // Check prerequisites first
        let supported = try await withCTAP2Session { session -> Bool in
            guard try await isSupported(session) else { return false }
            guard try await CTAP2.CredentialManagement.isReadOnlySupported(by: session) else {
                print("Persistent PUAT not supported - skipping")
                return false
            }
            return true
        }
        guard supported else { return }

        typealias Opaque128 = CTAP2.GetInfo.Opaque128

        // First session: setup and get PPUAT
        let testData:
            (
                ppuat: CTAP2.Token,
                credentialId: WebAuthn.CredentialDescriptor,
                rpIdHash: Data,
                identifier: Opaque128?,
                credStoreState: Opaque128?
            ) = try await withReconnectableCTAP2Session { session, reconnectWhenOverNFC in
                var session = session
                try await deleteAllCredentials(session)

                // Create test credential
                session = try await reconnectWhenOverNFC()
                try await createTestCredential(session)

                // Get credential info
                let credMgmt = try await getCredentialManagement(session)
                let rps = try await credMgmt.rps.enumerate()
                let credentials = try await credMgmt.credentials(for: rps[0].rpIdHash).enumerate()

                // Get PPUAT
                let ppuat = try await session.getPinUVToken(
                    using: .pin(defaultTestPin),
                    permissions: [.persistentCredentialManagement]
                )

                // Get encrypted fields
                let info = try await session.getInfo()
                let identifier = try info.encIdentifier.map { try $0.decrypted(using: ppuat) }
                let credStoreState = try info.encCredStoreState.map { try $0.decrypted(using: ppuat) }

                // Verify before reconnect
                try await verifyReadOnlyOperations(session: session, ppuat: ppuat, rpIdHash: rps[0].rpIdHash)

                return (ppuat, credentials[0].credentialId, rps[0].rpIdHash, identifier, credStoreState)
            }

        // Second session: verify PPUAT works after reconnect
        try await withCTAP2Session { session in
            try await verifyReadOnlyOperations(
                session: session,
                ppuat: testData.ppuat,
                rpIdHash: testData.rpIdHash
            )

            // Verify encrypted fields are consistent
            let info = try await session.getInfo()
            if let expected = testData.identifier {
                let identifier = try info.encIdentifier!.decrypted(using: testData.ppuat)
                #expect(identifier == expected)
            }
            if let expected = testData.credStoreState {
                let credStoreState = try info.encCredStoreState!.decrypted(using: testData.ppuat)
                #expect(credStoreState == expected)
            }
        }

        // Third session: cleanup and verify credStoreState changes
        try await withCTAP2Session { session in
            let credMgmt = try await getCredentialManagement(session)
            try await credMgmt.deleteCredential(testData.credentialId)

            if let original = testData.credStoreState {
                let info = try await session.getInfo()
                let newState = try info.encCredStoreState!.decrypted(using: testData.ppuat)
                #expect(newState != original)
            }
        }
    }
}

// MARK: - Test Fixture

private func withCredentialManagement(
    createCredential: Bool,
    _ body: (CTAP2.CredentialManagement, CTAP2.Session) async throws -> Void
) async throws {
    try await withReconnectableCTAP2Session { session, reconnectWhenOverNFC in
        var session = session
        guard try await isSupported(session) else { return }
        try await deleteAllCredentials(session)

        if createCredential {
            session = try await reconnectWhenOverNFC()
            try await createTestCredential(session)
        }

        let credMgmt = try await getCredentialManagement(session)
        try await body(credMgmt, session)

        try await deleteAllCredentials(session)
    }
}

// MARK: - Helpers

private func isSupported(_ session: CTAP2.Session) async throws -> Bool {
    guard try await CTAP2.CredentialManagement.isSupported(by: session) else {
        print("Credential management not supported - skipping")
        return false
    }
    let info = try await session.getInfo()
    try #require(info.options.clientPin == true, "PIN not set")
    return true
}

private func getCredentialManagement(_ session: CTAP2.Session) async throws -> CTAP2.CredentialManagement {
    let token = try await session.getPinUVToken(
        using: .pin(defaultTestPin),
        permissions: [.credentialManagement]
    )
    return try await session.credentialManagement(token: token)
}

private func createTestCredential(_ session: CTAP2.Session) async throws {
    let pinToken = try await session.getPinUVToken(
        using: .pin(defaultTestPin),
        permissions: [.makeCredential],
        rpId: testRpId
    )
    let params = CTAP2.MakeCredential.Parameters(
        clientDataHash: testClientDataHash,
        rp: testRp,
        user: testUser,
        pubKeyCredParams: [.es256],
        rk: true
    )
    print("👆 Touch YubiKey: creating test credential...")
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

private func verifyReadOnlyOperations(
    session: CTAP2.Session,
    ppuat: CTAP2.Token,
    rpIdHash: Data
) async throws {
    let credMgmt = try await session.credentialManagement(token: ppuat)

    // Read operations should work
    let metadata = try await credMgmt.getMetadata()
    #expect(metadata.existingCredentialsCount == 1)

    let rps = try await credMgmt.rps.enumerate()
    #expect(rps.count == 1)

    let credentials = try await credMgmt.credentials(for: rpIdHash).enumerate()
    #expect(credentials.count == 1)

    let credentialId = credentials[0].credentialId

    // Write operations should fail with pinAuthInvalid
    do {
        let user = WebAuthn.User(
            id: Data([0x01, 0x02, 0x03]),
            name: "X",
            displayName: "X"
        )
        try await credMgmt.updateUserInformation(credentialId: credentialId, user: user)
        Issue.record("updateUserInformation should fail with PPUAT")
    } catch {
        guard case .ctapError(.pinAuthInvalid, _) = error else {
            Issue.record("Expected pinAuthInvalid, got \(error)")
            throw error
        }
    }

    do {
        try await credMgmt.deleteCredential(credentialId)
        Issue.record("deleteCredential should fail with PPUAT")
    } catch {
        guard case .ctapError(.pinAuthInvalid, _) = error else {
            Issue.record("Expected pinAuthInvalid, got \(error)")
            throw error
        }
    }
}
