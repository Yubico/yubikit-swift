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

@Suite("WebAuthn LargeBlob Extension Tests", .serialized)
struct WebAuthnLargeBlobExtensionTests {

    @Test("LargeBlob - Store and Retrieve")
    func testLargeBlobStoreAndRetrieve() async throws {
        try await withReconnectableWebAuthnClient { client, session, reconnect in
            var (client, session) = (client, session)
            let rpId = "example.com"
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
            let createResponse = try await client.makeCredential(createOptions, authorization: .pin(defaultTestPin))
                .value

            guard createResponse.clientExtensionResults.largeBlob?.supported == true else {
                print("LargeBlob not supported - skipping")
                return
            }
            print("Credential supports largeBlob")

            let credentialId = createResponse.credentialId
            (client, session) = try await reconnect()

            // 2. Write blob
            let writeOptions = WebAuthn.Authentication.Options(
                challenge: randomBytes(count: 32),
                rpId: rpId,
                allowCredentials: [.init(id: credentialId)],
                extensions: .init(largeBlob: .write(testData))
            )

            print("Writing blob...")
            let writeResponse = try await client.getAssertion(writeOptions, authorization: .pin(defaultTestPin))
                .value[0]

            #expect(writeResponse.clientExtensionResults.largeBlob?.written == true)
            print("Blob written")

            (client, session) = try await reconnect()

            // 3. Read blob back
            let readOptions = WebAuthn.Authentication.Options(
                challenge: randomBytes(count: 32),
                rpId: rpId,
                allowCredentials: [.init(id: credentialId)],
                extensions: .init(largeBlob: .read)
            )

            print("Reading blob...")
            let readResponse = try await client.getAssertion(readOptions, authorization: .pin(defaultTestPin)).value[
                0
            ]

            #expect(readResponse.clientExtensionResults.largeBlob?.blob == testData)
            print("Blob retrieved and verified")

            (_, session) = try await reconnect()

            // 4. Delete blob via CTAP (WebAuthn API doesn't expose delete)
            let _ = try await session.getPinUVToken(
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

            (_, session) = try await reconnect()

            let deleteToken2 = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.largeBlobWrite],
                rpId: nil
            )

            try await session.deleteBlob(key: key, token: deleteToken2)
            print("Blob deleted via CTAP")

            // 5. Verify blob is gone
            let deletedBlob = try await session.getBlob(key: key)
            #expect(deletedBlob == nil, "Blob should be deleted")
            print("Verified blob no longer exists")
        }
    }

    @Test("LargeBlob - Multiple Credentials with Independent Blobs")
    func testLargeBlobMultipleCredentials() async throws {
        try await withReconnectableWebAuthnClient { client, _, reconnect in
            var client = client
            let rpId = "example.com"
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
            let createResponse1 = try await client.makeCredential(createOptions1, authorization: .pin(defaultTestPin))
                .value

            guard createResponse1.clientExtensionResults.largeBlob?.supported == true else {
                print("LargeBlob not supported - skipping")
                return
            }

            let credentialId1 = createResponse1.credentialId
            client = try await reconnect().client

            // Write blob to first credential
            let writeOptions1 = WebAuthn.Authentication.Options(
                challenge: randomBytes(count: 32),
                rpId: rpId,
                allowCredentials: [.init(id: credentialId1)],
                extensions: .init(largeBlob: .write(testData1))
            )
            _ = try await client.getAssertion(writeOptions1, authorization: .pin(defaultTestPin)).value[0]
            print("First blob written")

            client = try await reconnect().client

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
            let createResponse2 = try await client.makeCredential(createOptions2, authorization: .pin(defaultTestPin))
                .value
            let credentialId2 = createResponse2.credentialId
            client = try await reconnect().client

            // Write blob to second credential
            let writeOptions2 = WebAuthn.Authentication.Options(
                challenge: randomBytes(count: 32),
                rpId: rpId,
                allowCredentials: [.init(id: credentialId2)],
                extensions: .init(largeBlob: .write(testData2))
            )
            _ = try await client.getAssertion(writeOptions2, authorization: .pin(defaultTestPin)).value[0]
            print("Second blob written")

            client = try await reconnect().client

            // Read back both blobs
            let readOptions1 = WebAuthn.Authentication.Options(
                challenge: randomBytes(count: 32),
                rpId: rpId,
                allowCredentials: [.init(id: credentialId1)],
                extensions: .init(largeBlob: .read)
            )
            let readResponse1 = try await client.getAssertion(readOptions1, authorization: .pin(defaultTestPin))
                .value[0]
            #expect(readResponse1.clientExtensionResults.largeBlob?.blob == testData1)

            client = try await reconnect().client

            let readOptions2 = WebAuthn.Authentication.Options(
                challenge: randomBytes(count: 32),
                rpId: rpId,
                allowCredentials: [.init(id: credentialId2)],
                extensions: .init(largeBlob: .read)
            )
            let readResponse2 = try await client.getAssertion(readOptions2, authorization: .pin(defaultTestPin))
                .value[0]
            #expect(readResponse2.clientExtensionResults.largeBlob?.blob == testData2)

            print("Both blobs retrieved and verified independently")
        }
    }

    @Test("LargeBlob - Storage Full Error")
    func testLargeBlobStorageFull() async throws {
        try await withReconnectableWebAuthnClient { client, _, reconnect in
            var client = client
            let rpId = "example.com"

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
            let createResponse = try await client.makeCredential(createOptions, authorization: .pin(defaultTestPin))
                .value

            guard createResponse.clientExtensionResults.largeBlob?.supported == true else {
                print("LargeBlob not supported - skipping")
                return
            }

            let credentialId = createResponse.credentialId
            client = try await reconnect().client

            // Use 1MB of random data - guaranteed to exceed any YubiKey's storage
            // (YubiKey 5 series has ~4KB max largeBlob storage)
            let oversizedData = Data((0..<1_000_000).map { _ in UInt8.random(in: 0...255) })

            let writeOptions = WebAuthn.Authentication.Options(
                challenge: randomBytes(count: 32),
                rpId: rpId,
                allowCredentials: [.init(id: credentialId)],
                extensions: .init(largeBlob: .write(oversizedData))
            )

            print("Attempting to write oversized blob (\(oversizedData.count) bytes)...")
            do {
                _ = try await client.getAssertion(writeOptions, authorization: .pin(defaultTestPin)).value[0]
                Issue.record("Expected storageFull error for oversized blob")
            } catch let error as WebAuthn.ClientError {
                guard case .storageFull = error else {
                    Issue.record("Expected storageFull error, got: \(error)")
                    return
                }
                print("Correctly received storageFull error")
            }
        }
    }
}
