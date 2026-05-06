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

@Suite("Encrypted GetInfo Fields Tests", .serialized)
struct EncryptedFieldsTests {

    // MARK: - encIdentifier Tests

    @Test("Decrypt encIdentifier with persistent pinUvAuthToken")
    func testDecryptEncIdentifier() async throws {
        try await withCTAP2Session { session in
            let info = try await session.getInfo()
            try #require(info.encIdentifier != nil, "encIdentifier not supported")

            // Get persistent pinUvAuthToken (PPUAT) with pcmr permission
            let ppuat = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.persistentCredentialManagement]
            )

            let identifier = try info.encIdentifier!.decrypted(using: ppuat)
            print("✅ Decrypted device identifier: \(identifier)")

            // Decrypt again to verify same result
            let info2 = try await session.getInfo()
            let identifier2 = try info2.encIdentifier!.decrypted(using: ppuat)
            #expect(identifier == identifier2)
            print("✅ Decrypted identifier is consistent across GetInfo calls")
        }
    }

    // MARK: - encCredStoreState Tests

    @Test("Decrypt encCredStoreState with persistent pinUvAuthToken")
    func testDecryptEncCredStoreState() async throws {
        try await withCTAP2Session { session in
            let info = try await session.getInfo()
            try #require(info.encCredStoreState != nil, "encCredStoreState not supported")

            // Get persistent pinUvAuthToken (PPUAT) with pcmr permission
            let ppuat = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.persistentCredentialManagement]
            )

            let state = try info.encCredStoreState!.decrypted(using: ppuat)
            print("✅ Decrypted credential store state: \(state)")

            // Decrypt again to verify same result (without credential changes)
            let info2 = try await session.getInfo()
            let state2 = try info2.encCredStoreState!.decrypted(using: ppuat)
            #expect(state == state2)
            print("✅ Decrypted state is consistent when no credentials changed")
        }
    }

    // MARK: - Persistent Token Across Reconnects

    @Test("Persistent pinUvAuthToken works across reconnects")
    func testPersistentTokenAcrossReconnects() async throws {
        // First session: get PPUAT and decrypt fields
        typealias Opaque128 = CTAP2.GetInfo.Opaque128
        let (ppuat, identifier1, credStoreState1): (CTAP2.Token, Opaque128, Opaque128?) =
            try await withCTAP2Session { session in
                let info = try await session.getInfo()
                try #require(info.encIdentifier != nil, "encIdentifier not supported")

                let ppuat = try await session.getPinUVToken(
                    using: .pin(defaultTestPin),
                    permissions: [.persistentCredentialManagement]
                )

                let identifier = try info.encIdentifier!.decrypted(using: ppuat)
                let credStoreState = try info.encCredStoreState.map {
                    try $0.decrypted(using: ppuat)
                }

                return (ppuat, identifier, credStoreState)
            }

        // Second session: use same PPUAT to decrypt, verify same values
        try await withCTAP2Session { session in
            let info = try await session.getInfo()

            let identifier2 = try info.encIdentifier!.decrypted(using: ppuat)
            #expect(identifier1 == identifier2)
            print("✅ Device identifier consistent across reconnects")

            if let credStoreState1 = credStoreState1 {
                let credStoreState2 = try info.encCredStoreState!.decrypted(using: ppuat)
                #expect(credStoreState1 == credStoreState2)
                print("✅ Credential store state consistent across reconnects")
            }
        }
    }

    // MARK: - Credential Store State Change Detection

    @Test("credStoreState changes when credentials are added or deleted")
    func testCredStoreStateChangesOnCredentialLifecycle() async throws {
        try await withReconnectableCTAP2Session { session, reconnectWhenOverNFC in
            var session = session
            let info = try await session.getInfo()
            try #require(info.encCredStoreState != nil, "encCredStoreState not supported")

            guard try await CTAP2.CredentialManagement.isSupported(by: session) else {
                print("Credential management not supported - skipping")
                return
            }
            guard try await CTAP2.CredentialManagement.isReadOnlySupported(by: session) else {
                print("Persistent PUAT not supported - skipping")
                return
            }
            try #require(info.options.clientPin == true, "PIN not set")

            // Get PPUAT for decrypting credStoreState
            let ppuat = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.persistentCredentialManagement]
            )

            // Clean up any existing credentials
            let cmToken = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.credentialManagement]
            )
            let credMgmt = try await session.credentialManagement(token: cmToken)
            for try await rp in credMgmt.rps {
                for try await cred in credMgmt.credentials(for: rp.rpIdHash) {
                    try await credMgmt.deleteCredential(cred.credentialId)
                }
            }

            // 1. Get initial credStoreState
            let info1 = try await session.getInfo()
            let state1 = try info1.encCredStoreState!.decrypted(using: ppuat)
            print("✅ Initial credStoreState: \(state1)")

            // 2. Create discoverable credential (requires UP)
            session = try await reconnectWhenOverNFC()
            let makeCredToken = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.makeCredential],
                rpId: "test.example.com"
            )
            let params = CTAP2.MakeCredential.Parameters(
                clientDataHash: Data(repeating: 0xCD, count: 32),
                rp: WebAuthn.RelyingParty(id: "test.example.com", name: "Test"),
                user: WebAuthn.User(
                    id: Data([0x01, 0x02, 0x03]),
                    name: "test",
                    displayName: "Test"
                ),
                pubKeyCredParams: [.es256],
                rk: true
            )
            print("👆 Touch YubiKey: creating credential...")
            _ = try await session.makeCredential(parameters: params, token: makeCredToken).value

            // Verify state changed after credential creation
            let info2 = try await session.getInfo()
            let state2 = try info2.encCredStoreState!.decrypted(using: ppuat)
            #expect(state2 != state1)
            print("✅ credStoreState changed after credential creation: \(state2)")

            // 3. Delete credential via CredentialManagement (re-create after potential NFC reconnect)
            let deleteToken = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.credentialManagement]
            )
            let credMgmt2 = try await session.credentialManagement(token: deleteToken)
            let rps = try await credMgmt2.rps.enumerate()
            let creds = try await credMgmt2.credentials(for: rps[0].rpIdHash).enumerate()
            try await credMgmt2.deleteCredential(creds[0].credentialId)

            // Verify state changed after credential deletion
            let info3 = try await session.getInfo()
            let state3 = try info3.encCredStoreState!.decrypted(using: ppuat)
            #expect(state3 != state2)
            print("✅ credStoreState changed after credential deletion: \(state3)")
        }
    }
}
