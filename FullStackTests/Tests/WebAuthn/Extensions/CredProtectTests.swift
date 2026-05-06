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

@Suite("WebAuthn CredProtect Extension Tests", .serialized)
struct WebAuthnCredProtectExtensionTests {

    @Test("CredProtect - All Protection Levels")
    func testCredProtect() async throws {
        try await withReconnectableWebAuthnClient { client, _, reconnect in
            var client = client
            let rpId = "example.com"

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
            let createResponseNone = try await client.makeCredential(
                createOptionsNone,
                authorization: .pin(defaultTestPin)
            ).value
            #expect(createResponseNone.clientExtensionResults.credProtect?.policy == nil)
            print("No credProtect in response when not requested")

            client = try await reconnect().client

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
                extensions: .init(credProtect: .init(policy: .userVerificationOptional))
            )

            print("Creating credential with credProtect level 1...")
            let createResponse1 = try await client.makeCredential(createOptions1, authorization: .pin(defaultTestPin))
                .value

            if createResponse1.clientExtensionResults.credProtect?.policy == nil {
                print("credProtect not supported - skipping")
                return
            }
            #expect(createResponse1.clientExtensionResults.credProtect?.policy == .userVerificationOptional)
            print("CredProtect level 1 confirmed")

            client = try await reconnect().client

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
                extensions: .init(credProtect: .init(policy: .userVerificationOptionalWithCredentialIDList))
            )

            print("Creating credential with credProtect level 2...")
            let createResponse2 = try await client.makeCredential(createOptions2, authorization: .pin(defaultTestPin))
                .value

            #expect(
                createResponse2.clientExtensionResults.credProtect?.policy
                    == .userVerificationOptionalWithCredentialIDList
            )
            print("CredProtect level 2 confirmed")

            client = try await reconnect().client

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
                extensions: .init(credProtect: .init(policy: .userVerificationRequired))
            )

            print("Creating credential with credProtect level 3...")
            let createResponse3 = try await client.makeCredential(createOptions3, authorization: .pin(defaultTestPin))
                .value

            #expect(createResponse3.clientExtensionResults.credProtect?.policy == .userVerificationRequired)
            print("CredProtect level 3 confirmed")
        }
    }
}
