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

            let identifier: UUID = try info.encIdentifier!.decrypt(using: ppuat)
            print("✅ Decrypted device identifier: \(identifier)")

            // Decrypt again to verify same result
            let info2 = try await session.getInfo()
            let identifier2: UUID = try info2.encIdentifier!.decrypt(using: ppuat)
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

            let state: CTAP2.GetInfo.CredStoreState = try info.encCredStoreState!.decrypt(using: ppuat)
            print("✅ Decrypted credential store state: high=\(state.high), low=\(state.low)")

            // Decrypt again to verify same result (without credential changes)
            let info2 = try await session.getInfo()
            let state2: CTAP2.GetInfo.CredStoreState = try info2.encCredStoreState!.decrypt(using: ppuat)
            #expect(state == state2)
            print("✅ Decrypted state is consistent when no credentials changed")
        }
    }

    // MARK: - Persistent Token Across Reconnects

    @Test("Persistent pinUvAuthToken works across reconnects")
    func testPersistentTokenAcrossReconnects() async throws {
        // First session: get PPUAT and decrypt fields
        let (ppuat, identifier1, credStoreState1): (CTAP2.ClientPin.Token, UUID, CTAP2.GetInfo.CredStoreState?) =
            try await withCTAP2Session { session in
                let info = try await session.getInfo()
                try #require(info.encIdentifier != nil, "encIdentifier not supported")

                let ppuat = try await session.getPinUVToken(
                    using: .pin(defaultTestPin),
                    permissions: [.persistentCredentialManagement]
                )

                let identifier: UUID = try info.encIdentifier!.decrypt(using: ppuat)
                let credStoreState: CTAP2.GetInfo.CredStoreState? = try info.encCredStoreState.map {
                    try $0.decrypt(using: ppuat)
                }

                return (ppuat, identifier, credStoreState)
            }

        // Second session: use same PPUAT to decrypt, verify same values
        try await withCTAP2Session { session in
            let info = try await session.getInfo()

            let identifier2: UUID = try info.encIdentifier!.decrypt(using: ppuat)
            #expect(identifier1 == identifier2)
            print("✅ Device identifier consistent across reconnects")

            if let credStoreState1 = credStoreState1 {
                let credStoreState2: CTAP2.GetInfo.CredStoreState = try info.encCredStoreState!.decrypt(using: ppuat)
                #expect(credStoreState1 == credStoreState2)
                print("✅ Credential store state consistent across reconnects")
            }
        }
    }

    // MARK: - Credential Store State Change Detection

    @Test("credStoreState changes when credentials are added or deleted")
    func testCredStoreStateChangesOnCredentialLifecycle() async throws {
        // TODO: Implement when CredentialManagement API is added
        // 1. Get PPUAT and initial credStoreState
        // 2. Create discoverable credential -> verify state changes
        // 3. Delete credential via CredentialManagement -> verify state changes again
    }
}
