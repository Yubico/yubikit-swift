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

@Suite("WebAuthn PreviewSign Extension Tests", .serialized)
struct WebAuthnPreviewSignExtensionTests {

    // Only .esp256SplitARKGPlaceholder is currently supported by YubiKey firmware.
    private let generateKeyAlgorithms: [COSE.Algorithm] = [
        .esp256, .esp256SplitARKGPlaceholder, .es256,
    ]

    @Test("PreviewSign - No Output Without Extension Input", arguments: [true, false])
    func testNoOutputWithoutInput(discoverable: Bool) async throws {
        try await withReconnectableWebAuthnClient { client, session, _ in
            guard try await CTAP2.Extension.PreviewSign.isSupported(by: session) else {
                print("previewSign not supported - skipping")
                return
            }

            let createOptions = WebAuthn.Registration.Options(
                challenge: randomBytes(count: 32),
                rp: .init(id: "example.com", name: "PreviewSign Test"),
                user: .init(
                    id: randomBytes(count: 32),
                    name: "nopsign@example.com",
                    displayName: "No PreviewSign User"
                ),
                residentKey: discoverable ? .required : .discouraged,
                userVerification: .discouraged
            )

            let response = try await client.makeCredential(createOptions, authorization: .pin(defaultTestPin)).value

            #expect(response.clientExtensionResults.previewSign == nil)
        }
    }

    @Test("PreviewSign - GenerateKey", arguments: [true, false])
    func testGenerateKey(discoverable: Bool) async throws {
        try await withReconnectableWebAuthnClient { client, session, _ in
            guard try await CTAP2.Extension.PreviewSign.isSupported(by: session) else {
                print("previewSign not supported - skipping")
                return
            }

            let createOptions = WebAuthn.Registration.Options(
                challenge: randomBytes(count: 32),
                rp: .init(id: "example.com", name: "PreviewSign Test"),
                user: .init(
                    id: randomBytes(count: 32),
                    name: "psign@example.com",
                    displayName: "PreviewSign User"
                ),
                residentKey: discoverable ? .required : .discouraged,
                userVerification: .discouraged,
                extensions: .init(
                    previewSign: .generateKey(algorithms: generateKeyAlgorithms)
                )
            )

            let response = try await client.makeCredential(createOptions, authorization: .pin(defaultTestPin)).value

            let generatedKey = try assertGeneratedKey(response)
            #expect(
                generateKeyAlgorithms.contains(generatedKey.algorithm),
                "Algorithm \(generatedKey.algorithm) should be one of the requested algorithms"
            )
        }
    }

    // MARK: - Helpers

    private func assertGeneratedKey(
        _ response: WebAuthn.Registration.Response
    ) throws -> CTAP2.Extension.PreviewSign.GeneratedKey {
        guard let generatedKey = response.clientExtensionResults.previewSign?.generatedKey else {
            Issue.record("Expected previewSign generatedKey output")
            throw PreviewSignTestError.missingGeneratedKey
        }

        #expect(!generatedKey.keyHandle.isEmpty, "keyHandle should not be empty")
        #expect(!generatedKey.publicKey.isEmpty, "publicKey should not be empty")
        #expect(!generatedKey.attestationObject.isEmpty, "attestationObject should not be empty")

        return generatedKey
    }

    private enum PreviewSignTestError: Error {
        case missingGeneratedKey
    }
}
