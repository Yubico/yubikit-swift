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

@Suite("LargeBlobs Full Stack Tests", .serialized)
struct LargeBlobsFullStackTests {

    // MARK: - Read and Write

    @Test("Store and Retrieve Blob")
    func testStoreAndRetrieveBlob() async throws {
        try await withReconnectableCTAP2Session { session, reconnectWhenOverNFC in
            var session = session

            guard try await session.supportsLargeBlobs() else {
                print("LargeBlobs not supported - skipping")
                return
            }

            let info = try await session.getInfo()
            guard info.options.clientPin == true else {
                print("PIN not set - skipping (largeBlobWrite requires PIN)")
                return
            }

            let rpId = "largeblobs-test.example.com"
            let clientDataHash = Data(repeating: 0xCD, count: 32)
            let testData = Data("Hello from Swift LargeBlobs test!".utf8)

            // 1. Create credential with largeBlobKey extension
            session = try await reconnectWhenOverNFC()
            let pinToken = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.makeCredential, .largeBlobWrite],
                rpId: rpId
            )

            let largeBlobKey = CTAP2.Extension.LargeBlobKey()

            let makeCredParams = CTAP2.MakeCredential.Parameters(
                clientDataHash: clientDataHash,
                rp: WebAuthn.PublicKeyCredential.RPEntity(id: rpId, name: "LargeBlobs Test"),
                user: WebAuthn.PublicKeyCredential.UserEntity(
                    id: Data(repeating: 0x01, count: 32),
                    name: "blob@test.com",
                    displayName: "Blob Test User"
                ),
                pubKeyCredParams: [.es256],
                extensions: [largeBlobKey.makeCredential.input()],
                options: .init(rk: true)
            )

            print("👆 Touch YubiKey: creating credential with largeBlobKey...")
            let credential = try await session.makeCredential(parameters: makeCredParams, pinToken: pinToken).value

            guard let key = largeBlobKey.makeCredential.output(from: credential) else {
                Issue.record("Expected largeBlobKey in response")
                return
            }
            #expect(key.count == 32, "largeBlobKey should be 32 bytes")
            print("✅ Credential created with largeBlobKey")

            // 2. Store a blob
            session = try await reconnectWhenOverNFC()
            let writeToken = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.largeBlobWrite],
                rpId: nil
            )

            try await session.putBlob(key: key, data: testData, pinToken: writeToken)
            print("✅ Blob stored successfully")

            // 3. Read back the blob
            session = try await reconnectWhenOverNFC()
            let retrievedData = try await session.getBlob(key: key)

            #expect(retrievedData == testData, "Retrieved blob should match original")
            print("✅ Blob retrieved and verified")

            // 4. Delete the blob
            session = try await reconnectWhenOverNFC()
            let deleteToken = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.largeBlobWrite],
                rpId: nil
            )

            try await session.deleteBlob(key: key, pinToken: deleteToken)
            print("✅ Blob deleted")

            // 5. Verify blob is gone
            session = try await reconnectWhenOverNFC()
            let deletedBlob = try await session.getBlob(key: key)
            #expect(deletedBlob == nil, "Blob should be deleted")
            print("✅ Verified blob no longer exists")
        }
    }

    // MARK: - GetAssertion with LargeBlobKey

    @Test("GetAssertion with LargeBlobKey Extension")
    func testGetAssertionWithLargeBlobKey() async throws {
        try await withReconnectableCTAP2Session { session, reconnectWhenOverNFC in
            var session = session

            guard try await session.supportsLargeBlobs() else {
                print("LargeBlobs not supported - skipping")
                return
            }

            let info = try await session.getInfo()
            guard info.options.clientPin == true else {
                print("PIN not set - skipping")
                return
            }

            let rpId = "largeblobs-getassertion.example.com"
            let clientDataHash = Data(repeating: 0xCD, count: 32)
            let testData = Data("Blob data for GetAssertion test".utf8)

            // 1. Create credential with largeBlobKey
            session = try await reconnectWhenOverNFC()
            let pinToken = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.makeCredential, .largeBlobWrite, .getAssertion],
                rpId: rpId
            )

            let largeBlobKey = CTAP2.Extension.LargeBlobKey()

            let makeCredParams = CTAP2.MakeCredential.Parameters(
                clientDataHash: clientDataHash,
                rp: WebAuthn.PublicKeyCredential.RPEntity(id: rpId, name: "LargeBlobs GA Test"),
                user: WebAuthn.PublicKeyCredential.UserEntity(
                    id: Data(repeating: 0x02, count: 32),
                    name: "ga-blob@test.com",
                    displayName: "GA Blob User"
                ),
                pubKeyCredParams: [.es256],
                extensions: [largeBlobKey.makeCredential.input()],
                options: .init(rk: true)
            )

            print("👆 Touch YubiKey: creating credential...")
            let credential = try await session.makeCredential(parameters: makeCredParams, pinToken: pinToken).value

            guard let mcKey = largeBlobKey.makeCredential.output(from: credential) else {
                Issue.record("Expected largeBlobKey from MakeCredential")
                return
            }
            print("✅ Credential created")

            // 2. Store blob using the key from MakeCredential
            session = try await reconnectWhenOverNFC()
            let writeToken = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.largeBlobWrite],
                rpId: nil
            )
            try await session.putBlob(key: mcKey, data: testData, pinToken: writeToken)
            print("✅ Blob stored")

            // 3. GetAssertion with largeBlobKey extension to get the key again
            session = try await reconnectWhenOverNFC()
            let gaToken = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.getAssertion],
                rpId: rpId
            )

            let getAssertionParams = CTAP2.GetAssertion.Parameters(
                rpId: rpId,
                clientDataHash: clientDataHash,
                extensions: [largeBlobKey.getAssertion.input()],
                options: .init(uv: true)
            )

            print("👆 Touch YubiKey: authenticating with largeBlobKey...")
            let assertion = try await session.getAssertion(parameters: getAssertionParams, pinToken: gaToken).value

            guard let gaKey = largeBlobKey.getAssertion.output(from: assertion) else {
                Issue.record("Expected largeBlobKey from GetAssertion")
                return
            }
            #expect(gaKey == mcKey, "GetAssertion key should match MakeCredential key")
            print("✅ Got matching largeBlobKey from GetAssertion")

            // 4. Read blob using the key from GetAssertion
            session = try await reconnectWhenOverNFC()
            let retrievedData = try await session.getBlob(key: gaKey)
            #expect(retrievedData == testData, "Should retrieve correct blob data")
            print("✅ Retrieved blob using key from GetAssertion")

            // Cleanup
            session = try await reconnectWhenOverNFC()
            let cleanupToken = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.largeBlobWrite],
                rpId: nil
            )
            try await session.deleteBlob(key: gaKey, pinToken: cleanupToken)
            print("✅ Cleanup complete")
        }
    }

    // MARK: - Multiple Blobs

    @Test("Multiple Blobs for Different Credentials")
    func testMultipleBlobs() async throws {
        try await withReconnectableCTAP2Session { session, reconnectWhenOverNFC in
            var session = session

            guard try await session.supportsLargeBlobs() else {
                print("LargeBlobs not supported - skipping")
                return
            }

            let info = try await session.getInfo()
            guard info.options.clientPin == true else {
                print("PIN not set - skipping")
                return
            }

            let rpId = "largeblobs-multi.example.com"
            let clientDataHash = Data(repeating: 0xCD, count: 32)
            let testData1 = Data("First credential's blob data".utf8)
            let testData2 = Data("Second credential's blob data".utf8)

            // Create first credential
            session = try await reconnectWhenOverNFC()
            let pinToken1 = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.makeCredential, .largeBlobWrite],
                rpId: rpId
            )

            let largeBlobKey = CTAP2.Extension.LargeBlobKey()

            let params1 = CTAP2.MakeCredential.Parameters(
                clientDataHash: clientDataHash,
                rp: WebAuthn.PublicKeyCredential.RPEntity(id: rpId, name: "Multi Blob Test"),
                user: WebAuthn.PublicKeyCredential.UserEntity(
                    id: Data(repeating: 0x10, count: 32),
                    name: "user1@test.com",
                    displayName: "User 1"
                ),
                pubKeyCredParams: [.es256],
                extensions: [largeBlobKey.makeCredential.input()],
                options: .init(rk: true)
            )

            print("👆 Touch YubiKey: creating first credential...")
            let cred1 = try await session.makeCredential(parameters: params1, pinToken: pinToken1).value
            guard let key1 = largeBlobKey.makeCredential.output(from: cred1) else {
                Issue.record("Expected largeBlobKey for credential 1")
                return
            }
            print("✅ First credential created")

            // Create second credential
            session = try await reconnectWhenOverNFC()
            let pinToken2 = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.makeCredential, .largeBlobWrite],
                rpId: rpId
            )

            let params2 = CTAP2.MakeCredential.Parameters(
                clientDataHash: clientDataHash,
                rp: WebAuthn.PublicKeyCredential.RPEntity(id: rpId, name: "Multi Blob Test"),
                user: WebAuthn.PublicKeyCredential.UserEntity(
                    id: Data(repeating: 0x20, count: 32),
                    name: "user2@test.com",
                    displayName: "User 2"
                ),
                pubKeyCredParams: [.es256],
                extensions: [largeBlobKey.makeCredential.input()],
                options: .init(rk: true)
            )

            print("👆 Touch YubiKey: creating second credential...")
            let cred2 = try await session.makeCredential(parameters: params2, pinToken: pinToken2).value
            guard let key2 = largeBlobKey.makeCredential.output(from: cred2) else {
                Issue.record("Expected largeBlobKey for credential 2")
                return
            }
            print("✅ Second credential created")

            // Store blobs for both credentials
            session = try await reconnectWhenOverNFC()
            let writeToken = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.largeBlobWrite],
                rpId: nil
            )

            try await session.putBlob(key: key1, data: testData1, pinToken: writeToken)
            try await session.putBlob(key: key2, data: testData2, pinToken: writeToken)
            print("✅ Both blobs stored")

            // Verify blob array has 2 entries
            session = try await reconnectWhenOverNFC()
            let blobArray = try await session.readBlobArray()
            #expect(blobArray.entries.count >= 2, "Should have at least 2 blob entries")
            print("✅ Blob array has \(blobArray.entries.count) entries")

            // Retrieve and verify each blob
            let retrieved1 = try await session.getBlob(key: key1)
            let retrieved2 = try await session.getBlob(key: key2)

            #expect(retrieved1 == testData1, "First blob should match")
            #expect(retrieved2 == testData2, "Second blob should match")
            print("✅ Both blobs retrieved and verified")

            // Cleanup
            session = try await reconnectWhenOverNFC()
            let cleanupToken = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.largeBlobWrite],
                rpId: nil
            )
            try await session.deleteBlob(key: key1, pinToken: cleanupToken)
            try await session.deleteBlob(key: key2, pinToken: cleanupToken)
            print("✅ Cleanup complete")
        }
    }

    // MARK: - Error Cases

    @Test("Storage Full Returns LargeBlobStorageFull")
    func testStorageFull() async throws {
        try await withReconnectableCTAP2Session { session, reconnectWhenOverNFC in
            var session = session

            guard try await session.supportsLargeBlobs() else {
                print("LargeBlobs not supported - skipping")
                return
            }

            let info = try await session.getInfo()
            guard info.options.clientPin == true else {
                print("PIN not set - skipping")
                return
            }

            guard let maxSize = info.maxSerializedLargeBlobArray else {
                print("maxSerializedLargeBlobArray not available - skipping")
                return
            }

            // The max storage is for the CBOR-encoded array plus 16-byte checksum
            // Create data that when CBOR-encoded exceeds the max size
            let oversizedData = Data(repeating: 0x42, count: Int(maxSize))

            // Get a random key (we just need any 32-byte key for this test)
            let randomKey = Data((0..<32).map { _ in UInt8.random(in: 0...255) })

            session = try await reconnectWhenOverNFC()
            let pinToken = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.largeBlobWrite],
                rpId: nil
            )

            // Try to store oversized blob - should fail with largeBlobStorageFull
            do {
                try await session.putBlob(key: randomKey, data: oversizedData, pinToken: pinToken)
                Issue.record("Expected largeBlobStorageFull error")
            } catch let error as CTAP2.SessionError {
                guard case .ctapError(.largeBlobStorageFull, _) = error else {
                    Issue.record("Expected largeBlobStorageFull, got \(error)")
                    return
                }
                print("✅ Correctly received largeBlobStorageFull for oversized blob")
            }
        }
    }
}
