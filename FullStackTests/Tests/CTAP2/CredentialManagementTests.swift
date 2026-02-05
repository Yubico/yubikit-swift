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
private let testRp = WebAuthn.PublicKeyCredential.RPEntity(id: testRpId, name: "Test RP")

private let testUserId = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
private let testUserName = "testuser@example.com"
private let testUserDisplayName = "Test User"
private let testUser = WebAuthn.PublicKeyCredential.UserEntity(
    id: testUserId,
    name: testUserName,
    displayName: testUserDisplayName
)

// MARK: - Test Tags

extension Tag {
    @Tag static var credentialManagement: Tag
}

// MARK: - Tests

@Suite("Credential Management Full Stack Tests", .tags(.credentialManagement), .serialized)
struct CredentialManagementFullStackTests {

    // MARK: - Read Metadata Tests

    @Test("Read credential metadata with no credentials")
    func testReadMetadataEmpty() async throws {
        try await withCTAP2Session { session in
            guard try await requireCredentialManagementSupport(session) else { return }
            guard try await requirePinSet(session) else { return }
            try await deleteAllCredentials(session)

            let pinToken = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.credentialManagement]
            )
            let credMgmt = try await session.credentialManagement(pinToken: pinToken)

            let metadata = try await credMgmt.getMetadata()

            #expect(metadata.existingCredentialsCount == 0)
            #expect(metadata.maxRemainingCredentialsCount > 0)
        }
    }

    @Test("Read credential metadata with one credential")
    func testReadMetadataWithCredential() async throws {
        try await withReconnectableCTAP2Session { session, reconnectWhenOverNFC in
            var session = session
            guard try await requireCredentialManagementSupport(session) else { return }
            guard try await requirePinSet(session) else { return }
            try await deleteAllCredentials(session)

            // Create a test credential (requires UP)
            session = try await reconnectWhenOverNFC()
            try await createTestCredential(session)

            // Get fresh token for credential management
            let pinToken = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.credentialManagement]
            )
            let credMgmt = try await session.credentialManagement(pinToken: pinToken)

            let metadata = try await credMgmt.getMetadata()

            #expect(metadata.existingCredentialsCount == 1)
            #expect(metadata.maxRemainingCredentialsCount > 0)

            // Cleanup
            try await deleteAllCredentials(session)
        }
    }

    // MARK: - Enumerate RPs Tests

    @Test("Enumerate RPs returns empty when no credentials")
    func testEnumerateRPsEmpty() async throws {
        try await withCTAP2Session { session in
            guard try await requireCredentialManagementSupport(session) else { return }
            guard try await requirePinSet(session) else { return }
            try await deleteAllCredentials(session)

            let pinToken = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.credentialManagement]
            )
            let credMgmt = try await session.credentialManagement(pinToken: pinToken)

            let rps = try await credMgmt.enumerateRPs()

            #expect(rps.isEmpty)
        }
    }

    @Test("Enumerate RPs returns RP after credential creation")
    func testEnumerateRPs() async throws {
        try await withReconnectableCTAP2Session { session, reconnectWhenOverNFC in
            var session = session
            guard try await requireCredentialManagementSupport(session) else { return }
            guard try await requirePinSet(session) else { return }
            try await deleteAllCredentials(session)

            // Create test credential (requires UP)
            session = try await reconnectWhenOverNFC()
            try await createTestCredential(session)

            // Get fresh token for credential management
            let pinToken = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.credentialManagement]
            )
            let credMgmt = try await session.credentialManagement(pinToken: pinToken)

            let rps = try await credMgmt.enumerateRPs()

            #expect(rps.count == 1)
            #expect(rps[0].rp.id == testRpId)
            #expect(rps[0].rpIdHash.count == 32)  // SHA-256 hash

            // Cleanup
            try await deleteAllCredentials(session)
        }
    }

    // MARK: - AsyncSequence Tests

    @Test("Enumerate RPs using AsyncSequence")
    func testEnumerateRPsAsyncSequence() async throws {
        try await withReconnectableCTAP2Session { session, reconnectWhenOverNFC in
            var session = session
            guard try await requireCredentialManagementSupport(session) else { return }
            guard try await requirePinSet(session) else { return }
            try await deleteAllCredentials(session)

            // Create test credential (requires UP)
            session = try await reconnectWhenOverNFC()
            try await createTestCredential(session)

            // Get fresh token for credential management
            let pinToken = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.credentialManagement]
            )
            let credMgmt = try await session.credentialManagement(pinToken: pinToken)

            // Use AsyncSequence to iterate RPs
            var rpCount = 0
            for try await rp in credMgmt.rps {
                #expect(rp.rp.id == testRpId)
                #expect(rp.rpIdHash.count == 32)
                rpCount += 1
            }

            #expect(rpCount == 1)

            // Cleanup
            try await deleteAllCredentials(session)
        }
    }

    @Test("Enumerate credentials using AsyncSequence")
    func testEnumerateCredentialsAsyncSequence() async throws {
        try await withReconnectableCTAP2Session { session, reconnectWhenOverNFC in
            var session = session
            guard try await requireCredentialManagementSupport(session) else { return }
            guard try await requirePinSet(session) else { return }
            try await deleteAllCredentials(session)

            // Create test credential (requires UP)
            session = try await reconnectWhenOverNFC()
            try await createTestCredential(session)

            // Get fresh token for credential management
            let pinToken = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.credentialManagement]
            )
            let credMgmt = try await session.credentialManagement(pinToken: pinToken)

            // Get the RP first
            let rps = try await credMgmt.enumerateRPs()
            #expect(rps.count == 1)

            // Use AsyncSequence to iterate credentials
            var credCount = 0
            for try await cred in credMgmt.credentials(for: rps[0].rpIdHash) {
                #expect(cred.user.id == testUserId)
                #expect(cred.user.name == testUserName)
                #expect(cred.user.displayName == testUserDisplayName)
                credCount += 1
            }

            #expect(credCount == 1)

            // Cleanup
            try await deleteAllCredentials(session)
        }
    }

    @Test("AsyncSequence returns empty for no credentials")
    func testAsyncSequenceEmpty() async throws {
        try await withCTAP2Session { session in
            guard try await requireCredentialManagementSupport(session) else { return }
            guard try await requirePinSet(session) else { return }
            try await deleteAllCredentials(session)

            let pinToken = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.credentialManagement]
            )
            let credMgmt = try await session.credentialManagement(pinToken: pinToken)

            // Verify empty iteration
            var rpCount = 0
            for try await _ in credMgmt.rps {
                rpCount += 1
            }

            #expect(rpCount == 0)
        }
    }

    // MARK: - Enumerate Credentials Tests

    @Test("Enumerate credentials for RP")
    func testEnumerateCredentials() async throws {
        try await withReconnectableCTAP2Session { session, reconnectWhenOverNFC in
            var session = session
            guard try await requireCredentialManagementSupport(session) else { return }
            guard try await requirePinSet(session) else { return }
            try await deleteAllCredentials(session)

            // Create test credential (requires UP)
            session = try await reconnectWhenOverNFC()
            try await createTestCredential(session)

            // Get fresh token for credential management
            let pinToken = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.credentialManagement]
            )
            let credMgmt = try await session.credentialManagement(pinToken: pinToken)

            // First get the RP
            let rps = try await credMgmt.enumerateRPs()
            #expect(rps.count == 1)

            // Enumerate credentials for the RP
            let credentials = try await credMgmt.enumerateCredentials(rpIdHash: rps[0].rpIdHash)

            #expect(credentials.count == 1)
            #expect(credentials[0].user.id == testUserId)
            #expect(credentials[0].user.name == testUserName)
            #expect(credentials[0].user.displayName == testUserDisplayName)
            #expect(credentials[0].credentialId.id.count > 0)

            // Cleanup
            try await deleteAllCredentials(session)
        }
    }

    // MARK: - Delete Credential Tests

    @Test("Delete credential removes it from authenticator")
    func testDeleteCredential() async throws {
        try await withReconnectableCTAP2Session { session, reconnectWhenOverNFC in
            var session = session
            guard try await requireCredentialManagementSupport(session) else { return }
            guard try await requirePinSet(session) else { return }
            try await deleteAllCredentials(session)

            // Create test credential (requires UP)
            session = try await reconnectWhenOverNFC()
            try await createTestCredential(session)

            // Get fresh token for credential management
            var pinToken = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.credentialManagement]
            )
            var credMgmt = try await session.credentialManagement(pinToken: pinToken)

            // Verify credential exists
            var metadata = try await credMgmt.getMetadata()
            #expect(metadata.existingCredentialsCount == 1)

            // Get the credential to delete
            let rps = try await credMgmt.enumerateRPs()
            let credentials = try await credMgmt.enumerateCredentials(rpIdHash: rps[0].rpIdHash)
            let credentialToDelete = credentials[0]

            // Delete the credential
            try await credMgmt.deleteCredential(credentialToDelete.credentialId)

            // Get new token and verify credential is gone
            pinToken = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.credentialManagement]
            )
            credMgmt = try await session.credentialManagement(pinToken: pinToken)

            metadata = try await credMgmt.getMetadata()
            #expect(metadata.existingCredentialsCount == 0)
        }
    }

    // MARK: - Update User Information Tests

    @Test("Update user information changes display name")
    func testUpdateUserInformation() async throws {
        try await withReconnectableCTAP2Session { session, reconnectWhenOverNFC in
            var session = session
            guard try await requireCredentialManagementSupport(session) else { return }

            // Check if update is supported
            guard try await CTAP2.CredentialManagement.isUpdateSupported(by: session) else {
                print("Update user information not supported - skipping")
                return
            }

            guard try await requirePinSet(session) else { return }
            try await deleteAllCredentials(session)

            // Create test credential (requires UP)
            session = try await reconnectWhenOverNFC()
            try await createTestCredential(session)

            // Get fresh token for credential management
            var pinToken = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.credentialManagement]
            )
            var credMgmt = try await session.credentialManagement(pinToken: pinToken)

            // Get the credential
            let rps = try await credMgmt.enumerateRPs()
            let credentials = try await credMgmt.enumerateCredentials(rpIdHash: rps[0].rpIdHash)
            let credentialToUpdate = credentials[0]

            // Create updated user info
            let updatedUser = WebAuthn.PublicKeyCredential.UserEntity(
                id: testUserId,
                name: "UPDATED NAME",
                displayName: "UPDATED DISPLAY NAME"
            )

            // Update user information
            try await credMgmt.updateUserInformation(
                credentialId: credentialToUpdate.credentialId,
                user: updatedUser
            )

            // Get new token and verify update
            pinToken = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.credentialManagement]
            )
            credMgmt = try await session.credentialManagement(pinToken: pinToken)

            let rpsAfter = try await credMgmt.enumerateRPs()
            let updatedCredentials = try await credMgmt.enumerateCredentials(rpIdHash: rpsAfter[0].rpIdHash)

            #expect(updatedCredentials[0].user.id == testUserId)
            #expect(updatedCredentials[0].user.name == "UPDATED NAME")
            #expect(updatedCredentials[0].user.displayName == "UPDATED DISPLAY NAME")

            // Cleanup
            try await deleteAllCredentials(session)
        }
    }

    // MARK: - Full Management Flow Test

    @Test("Full credential management workflow")
    func testFullManagementWorkflow() async throws {
        try await withReconnectableCTAP2Session { session, reconnectWhenOverNFC in
            var session = session
            guard try await requireCredentialManagementSupport(session) else { return }
            guard try await requirePinSet(session) else { return }
            try await deleteAllCredentials(session)

            // 1. Verify no credentials exist
            var pinToken = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.credentialManagement]
            )
            var credMgmt = try await session.credentialManagement(pinToken: pinToken)
            var rps = try await credMgmt.enumerateRPs()
            #expect(rps.isEmpty)

            // 2. Create first credential (requires UP)
            session = try await reconnectWhenOverNFC()
            try await createTestCredential(session)

            // 3. Verify credential was created
            pinToken = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.credentialManagement]
            )
            credMgmt = try await session.credentialManagement(pinToken: pinToken)

            rps = try await credMgmt.enumerateRPs()
            #expect(rps.count == 1)
            #expect(rps[0].rp.id == testRpId)

            let credentials = try await credMgmt.enumerateCredentials(rpIdHash: rps[0].rpIdHash)
            #expect(credentials.count == 1)

            let metadata = try await credMgmt.getMetadata()
            #expect(metadata.existingCredentialsCount == 1)

            // 4. Delete the credential
            try await credMgmt.deleteCredential(credentials[0].credentialId)

            // 5. Verify credential was deleted
            pinToken = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.credentialManagement]
            )
            credMgmt = try await session.credentialManagement(pinToken: pinToken)

            rps = try await credMgmt.enumerateRPs()
            #expect(rps.isEmpty)

            let finalMetadata = try await credMgmt.getMetadata()
            #expect(finalMetadata.existingCredentialsCount == 0)
        }
    }
}

// MARK: - Helpers

private func requireCredentialManagementSupport(_ session: CTAP2.Session) async throws -> Bool {
    guard try await CTAP2.CredentialManagement.isSupported(by: session) else {
        print("Credential management not supported - skipping")
        return false
    }
    return true
}

private func requirePinSet(_ session: CTAP2.Session) async throws -> Bool {
    let info = try await session.getInfo()
    guard info.options.clientPin == true else {
        print("PIN not set - skipping (run testClientPinSetup first)")
        return false
    }
    return true
}

private func createTestCredential(_ session: CTAP2.Session) async throws {
    // Get PIN token for makeCredential
    let pinToken = try await session.getPinUVToken(
        using: .pin(defaultTestPin),
        permissions: [.makeCredential],
        rpId: testRpId
    )

    // Create a discoverable (resident) credential
    let params = CTAP2.MakeCredential.Parameters(
        clientDataHash: testClientDataHash,
        rp: testRp,
        user: testUser,
        pubKeyCredParams: [.es256],
        options: .init(rk: true)
    )

    print("👆 Touch YubiKey: creating test credential...")
    _ = try await session.makeCredential(parameters: params, pinToken: pinToken).value
    print("✅ Test credential created")
}

private func deleteAllCredentials(_ session: CTAP2.Session) async throws {
    let pinToken = try await session.getPinUVToken(
        using: .pin(defaultTestPin),
        permissions: .credentialManagement
    )
    let credMgmt = try await session.credentialManagement(pinToken: pinToken)

    // Use AsyncSequence to enumerate and delete all credentials
    for try await rp in credMgmt.rps {
        for try await credential in credMgmt.credentials(for: rp.rpIdHash) {
            try await credMgmt.deleteCredential(credential.credentialId)
        }
    }
}
