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

@Suite("WebAuthn MinPinLength Extension Tests", .serialized)
struct WebAuthnMinPinLengthExtensionTests {

    @Test("MinPinLength - Returns Value When RP Configured")
    func testMinPinLength() async throws {
        // This test requires authenticatorConfig to configure the RP ID first
        try await withReconnectableCTAP2Session { session, reconnectWhenOverNFC in
            var session = session

            guard try await CTAP2.Extension.MinPinLength.isSupported(by: session) else {
                print("minPinLength not supported - skipping")
                return
            }

            guard try await CTAP2.Config.isSupported(by: session) else {
                print("authenticatorConfig not supported - skipping")
                return
            }

            let info = try await session.getInfo()
            guard info.options.clientPin == true else {
                print("PIN not set - skipping")
                return
            }

            let rpId = "example.com"

            // Configure the RP ID to receive minPinLength (requires CTAP direct call)
            let configToken = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.authenticatorConfig]
            )
            let config = try await session.config(token: configToken)
            try await config.setMinPINLength(rpIDs: [rpId])
            print("RP configured for minPinLength")

            session = try await reconnectWhenOverNFC()

            // Now use WebAuthn client
            let client = WebAuthn.Client(
                session: session,
                origin: try WebAuthn.Origin("https://\(rpId)"),
                allowedExtensions: [.minPinLength],
                isPublicSuffix: { _ in false }
            )

            let createOptions = WebAuthn.Registration.Options(
                challenge: randomBytes(count: 32),
                rp: .init(id: rpId, name: "MinPinLength Test"),
                user: .init(
                    id: randomBytes(count: 32),
                    name: "minpin@example.com",
                    displayName: "MinPin User"
                ),
                residentKey: .required,
                extensions: .init(minPinLength: true)
            )

            print("Creating credential with minPinLength extension...")
            let createResponse = try await client.makeCredential(createOptions, authorization: .pin(defaultTestPin))
                .value

            guard let length = createResponse.clientExtensionResults.minPinLength?.length else {
                Issue.record("minPinLength should be returned for configured RP")
                return
            }

            #expect(length >= 4, "minPinLength should be at least 4")
            if let infoMinPinLength = info.minPinLength {
                #expect(length == infoMinPinLength)
            }
            print("minPinLength returned: \(length)")
        }
    }
}
