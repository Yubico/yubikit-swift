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

@Suite("WebAuthn PRF Extension Tests", .serialized)
struct WebAuthnPRFExtensionTests {

    @Test("PRF - Enable at Registration and Derive Secrets at Authentication")
    func testPRF() async throws {
        try await withReconnectableWebAuthnClient { client, _, reconnect in
            var client = client
            let rpId = "example.com"

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
            let createResponse = try await client.makeCredential(createOptions, authorization: .pin(defaultTestPin))
                .value

            guard createResponse.clientExtensionResults.prf?.enabled == true else {
                print("PRF not supported - skipping")
                return
            }
            print("PRF enabled")

            let credentialId = createResponse.credentialId
            client = try await reconnect().client

            // 2. Authenticate with PRF using one secret
            let secret1 = Data(repeating: 0xAA, count: 32)

            let authOptions1 = WebAuthn.Authentication.Options(
                challenge: randomBytes(count: 32),
                rpId: rpId,
                allowCredentials: [.init(id: credentialId)],
                extensions: .init(prf: .eval(first: secret1))
            )

            print("Authenticating with PRF (one secret)...")
            let authResponse1 = try await client.getAssertion(authOptions1, authorization: .pin(defaultTestPin))
                .value[0]

            guard let prfOutput1 = authResponse1.clientExtensionResults.prf else {
                Issue.record("Expected PRF output in first assertion")
                return
            }
            #expect(prfOutput1.results.first.count == 32)
            print("PRF secrets.first: \(prfOutput1.results.first.prefix(8).hexEncodedString)...")

            client = try await reconnect().client

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
            let authResponse2 = try await client.getAssertion(authOptions2, authorization: .pin(defaultTestPin))
                .value[0]

            guard let prfOutput2 = authResponse2.clientExtensionResults.prf else {
                Issue.record("Expected PRF output in second assertion")
                return
            }

            // Same secret1 should produce same output
            #expect(prfOutput2.results.first == prfOutput1.results.first, "Same secret should produce same output")
            #expect(prfOutput2.results.second != nil, "Should have second output")
            #expect(
                prfOutput2.results.second != prfOutput2.results.first,
                "Different secrets should produce different outputs"
            )

            print("PRF evalByCredential verified")
        }
    }

    @Test("PRF MC - Derive Secrets at Registration (CTAP2.2)")
    func testPRFMakeCredential() async throws {
        try await withReconnectableWebAuthnClient { client, _, reconnect in
            var client = client
            let rpId = "example.com"

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
            let createResponse = try await client.makeCredential(createOptions, authorization: .pin(defaultTestPin))
                .value

            guard let prfOutput = createResponse.clientExtensionResults.prf,
                let mcSecrets = prfOutput.results
            else {
                print("hmac-secret-mc not supported - skipping")
                return
            }

            #expect(mcSecrets.first.count == 32)
            #expect(mcSecrets.second?.count == 32)
            print("PRF MakeCredential derived secrets")

            let credentialId = createResponse.credentialId
            client = try await reconnect().client

            // 2. Authenticate with same secrets and verify determinism
            let authOptions = WebAuthn.Authentication.Options(
                challenge: randomBytes(count: 32),
                rpId: rpId,
                allowCredentials: [.init(id: credentialId)],
                extensions: .init(prf: .eval(first: secret1, second: secret2))
            )

            print("Authenticating with PRF (verifying determinism)...")
            let authResponse = try await client.getAssertion(authOptions, authorization: .pin(defaultTestPin)).value[
                0
            ]

            guard let gaOutput = authResponse.clientExtensionResults.prf else {
                Issue.record("Expected PRF output in assertion")
                return
            }

            #expect(gaOutput.results == mcSecrets, "GetAssertion secrets should match MakeCredential secrets")
            print("PRF outputs are deterministic")
        }
    }
}
