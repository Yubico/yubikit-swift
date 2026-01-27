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

@Suite("MinPinLength Full Stack Tests", .serialized)
struct MinPinLengthFullStackTests {

    // MARK: - Configured RP Test

    @Test("MinPinLength returns value when RP is configured")
    func testMinPinLengthWithConfiguredRP() async throws {
        try await withCTAP2Session { session in
            guard try await CTAP2.Extension.MinPinLength.isSupported(by: session) else {
                print("minPinLength not supported - skipping")
                return
            }

            guard try await CTAP2.Config.Operations.isSupported(by: session) else {
                print("authenticatorConfig not supported - skipping")
                return
            }

            let info = try await session.getInfo()
            guard info.options.clientPin == true else {
                print("PIN not set - skipping")
                return
            }

            let rpId = "minpinlength-configured-test.example.com"

            // Configure the RP ID to receive minPinLength
            let configToken = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.authenticatorConfig]
            )
            let config = try await CTAP2.Config.Operations(session: session, pinToken: configToken)
            try await config.setMinPINLength(rpIDs: [rpId])

            // Create credential with minPinLength extension
            let makeCredToken = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.makeCredential],
                rpId: rpId
            )

            let minPinLength = try await CTAP2.Extension.MinPinLength(session: session)

            let makeCredParams = CTAP2.MakeCredential.Parameters(
                clientDataHash: Data(repeating: 0xCD, count: 32),
                rp: WebAuthn.PublicKeyCredential.RPEntity(id: rpId, name: "MinPinLength Test"),
                user: WebAuthn.PublicKeyCredential.UserEntity(
                    id: Data(repeating: 0x01, count: 32),
                    name: "minpin@test.com",
                    displayName: "MinPinLength Test User"
                ),
                pubKeyCredParams: [.es256],
                extensions: [minPinLength.makeCredential.input()]
            )

            print("👆 Touch YubiKey: creating credential with minPinLength extension...")
            let credential = try await session.makeCredential(
                parameters: makeCredParams,
                pinToken: makeCredToken
            ).value

            let length = minPinLength.makeCredential.output(from: credential)

            // Since we configured the RP ID, we should get the minPinLength back
            #expect(length != nil, "minPinLength should be returned for configured RP")
            if let length {
                #expect(length >= 4, "minPinLength should be at least 4")
                if let infoMinPinLength = info.minPinLength {
                    #expect(length == infoMinPinLength, "Should match info.minPinLength")
                }
                print("✅ minPinLength returned: \(length)")
            }
        }
    }

}
