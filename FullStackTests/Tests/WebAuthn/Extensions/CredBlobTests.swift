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

@Suite("WebAuthn CredBlob Extension Tests", .serialized)
struct WebAuthnCredBlobExtensionTests {

    @Test("CredBlob - Store at Registration and Retrieve at Authentication")
    func testCredBlobStoreAndRetrieve() async throws {
        try await withReconnectableWebAuthnClient { client, _, reconnect in
            var client = client
            let rpId = "example.com"
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
            let createResponse = try await client.makeCredential(createOptions, authorization: .pin(defaultTestPin))
                .value

            guard createResponse.clientExtensionResults.credBlob?.stored == true else {
                print("credBlob not supported - skipping")
                return
            }
            print("CredBlob stored")

            client = try await reconnect().client

            // 2. Retrieve credBlob at authentication
            let authOptions = WebAuthn.Authentication.Options(
                challenge: randomBytes(count: 32),
                rpId: rpId,
                extensions: .init(getCredBlob: true)
            )

            print("Authenticating to retrieve credBlob...")
            let authResponse = try await client.getAssertion(authOptions, authorization: .pin(defaultTestPin)).value[
                0
            ]

            #expect(authResponse.clientExtensionResults.credBlob?.blob == testBlob)
            print("CredBlob retrieved and verified")
        }
    }

    @Test("CredBlob - Not Returned Without Extension")
    func testCredBlobNotReturnedWithoutExtension() async throws {
        try await withReconnectableWebAuthnClient { client, _, reconnect in
            var client = client
            let rpId = "example.com"
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
            let createResponse = try await client.makeCredential(createOptions, authorization: .pin(defaultTestPin))
                .value

            guard createResponse.clientExtensionResults.credBlob?.stored == true else {
                print("credBlob not supported - skipping")
                return
            }

            client = try await reconnect().client

            // 2. Authenticate WITHOUT requesting credBlob (no getCredBlob: true)
            let authOptions = WebAuthn.Authentication.Options(
                challenge: randomBytes(count: 32),
                rpId: rpId
            )

            print("Authenticating without credBlob extension...")
            let authResponse = try await client.getAssertion(authOptions, authorization: .pin(defaultTestPin)).value[
                0
            ]

            #expect(authResponse.clientExtensionResults.credBlob?.blob == nil)
            print("CredBlob not returned without extension")
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

            let rpId = "example.com"
            let oversizedBlob = Data(repeating: 0xFF, count: Int(maxLength) + 1)

            let client = WebAuthn.Client(
                session: session,
                origin: try WebAuthn.Origin("https://\(rpId)"),
                allowedExtensions: [.credBlob],
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
                _ = try await client.makeCredential(createOptions, authorization: .pin(defaultTestPin)).value
                Issue.record("Expected error for oversized credBlob")
            } catch {
                print("Correctly rejected oversized credBlob: \(error)")
            }
        }
    }
}
