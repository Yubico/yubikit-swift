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

@Suite("CTAP2 Extension Full Stack Tests", .serialized)
struct CTAP2ExtensionFullStackTests {

    // MARK: - CredProtect Extension Tests

    @Test("CredProtect Extension")
    func testCredProtect() async throws {
        try await withCTAP2Session { session in
            guard try await CTAP2.Extension.CredProtect.isSupported(by: session) else {
                print("Device doesn't support credProtect - skipping")
                return
            }

            let clientDataHash = Data(repeating: 0xCD, count: 32)
            let rpId = "credprotect-test.com"

            // Create credProtect instance for output checking
            let credProtect1 = try await CTAP2.Extension.CredProtect(
                level: .userVerificationOptional,
                session: session
            )

            // Test 1: No extension - should not return credProtect
            print("👆 Touch YubiKey: credential without credProtect extension...")
            let noExtParams = CTAP2.MakeCredential.Parameters(
                clientDataHash: clientDataHash,
                rp: WebAuthn.PublicKeyCredential.RPEntity(id: rpId, name: "CredProtect Test"),
                user: WebAuthn.PublicKeyCredential.UserEntity(
                    id: Data(repeating: 0x00, count: 32),
                    name: "noext@test.com",
                    displayName: "No Extension User"
                ),
                pubKeyCredParams: [.es256],
                options: .init(rk: false)
            )
            let noExtResponse = try await session.makeCredential(parameters: noExtParams).value
            #expect(credProtect1.output(from: noExtResponse) == nil)
            print("✅ No credProtect in response when not requested")

            // Test 2: Level 1 (userVerificationOptional)
            print("👆 Touch YubiKey: credProtect level 1...")
            let level1Params = CTAP2.MakeCredential.Parameters(
                clientDataHash: clientDataHash,
                rp: WebAuthn.PublicKeyCredential.RPEntity(id: rpId, name: "CredProtect Test"),
                user: WebAuthn.PublicKeyCredential.UserEntity(
                    id: Data(repeating: 0x01, count: 32),
                    name: "level1@test.com",
                    displayName: "Level 1 User"
                ),
                pubKeyCredParams: [.es256],
                extensions: [credProtect1.input()],
                options: .init(rk: false)
            )
            let level1Response = try await session.makeCredential(parameters: level1Params).value
            #expect(credProtect1.output(from: level1Response) == .userVerificationOptional)
            print("✅ CredProtect level 1 confirmed")

            // Test 3: Level 2 (userVerificationOptionalWithCredentialIDList)
            let credProtect2 = try await CTAP2.Extension.CredProtect(
                level: .userVerificationOptionalWithCredentialIDList,
                session: session
            )
            print("👆 Touch YubiKey: credProtect level 2...")
            let level2Params = CTAP2.MakeCredential.Parameters(
                clientDataHash: clientDataHash,
                rp: WebAuthn.PublicKeyCredential.RPEntity(id: rpId, name: "CredProtect Test"),
                user: WebAuthn.PublicKeyCredential.UserEntity(
                    id: Data(repeating: 0x02, count: 32),
                    name: "level2@test.com",
                    displayName: "Level 2 User"
                ),
                pubKeyCredParams: [.es256],
                extensions: [credProtect2.input()],
                options: .init(rk: false)
            )
            let level2Response = try await session.makeCredential(parameters: level2Params).value
            #expect(credProtect2.output(from: level2Response) == .userVerificationOptionalWithCredentialIDList)
            print("✅ CredProtect level 2 confirmed")

            // Test 4: Level 3 (userVerificationRequired) with resident key
            let info = try await session.getInfo()
            guard info.options.clientPin == true else {
                print("PIN not set - skipping level 3 test (requires PIN for rk: true)")
                return
            }

            let pinToken = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.makeCredential, .credentialManagement],
                rpId: rpId
            )

            let credProtect3 = try await CTAP2.Extension.CredProtect(
                level: .userVerificationRequired,
                session: session
            )
            print("👆 Touch YubiKey: credProtect level 3 with resident key...")
            let level3Params = CTAP2.MakeCredential.Parameters(
                clientDataHash: clientDataHash,
                rp: WebAuthn.PublicKeyCredential.RPEntity(id: rpId, name: "CredProtect Test"),
                user: WebAuthn.PublicKeyCredential.UserEntity(
                    id: Data(repeating: 0x03, count: 32),
                    name: "level3@test.com",
                    displayName: "Level 3 User"
                ),
                pubKeyCredParams: [.es256],
                extensions: [credProtect3.input()],
                options: .init(rk: true)
            )
            let level3Response = try await session.makeCredential(parameters: level3Params, pinToken: pinToken).value
            #expect(credProtect3.output(from: level3Response) == .userVerificationRequired)
            print("✅ CredProtect level 3 confirmed")
        }
    }

    // MARK: - HmacSecret MakeCredential Extension Tests

    @Test("HmacSecret - Request Support at MakeCredential")
    func testHmacSecretRequestSupport() async throws {
        try await withCTAP2Session { session in
            guard try await CTAP2.Extension.HmacSecret.isSupported(by: session) else {
                print("Device doesn't support hmac-secret - skipping")
                return
            }

            let clientDataHash = Data(repeating: 0xCD, count: 32)
            let hmacSecret = CTAP2.Extension.HmacSecret()
            let hmacSecretInput = hmacSecret.makeCredential.input()

            let params = CTAP2.MakeCredential.Parameters(
                clientDataHash: clientDataHash,
                rp: WebAuthn.PublicKeyCredential.RPEntity(id: "hmac-secret-test.com", name: "HmacSecret Test"),
                user: WebAuthn.PublicKeyCredential.UserEntity(
                    id: Data(repeating: 0x10, count: 32),
                    name: "hmac@test.com",
                    displayName: "HmacSecret User"
                ),
                pubKeyCredParams: [.es256],
                extensions: [hmacSecretInput],
                options: .init(rk: false)
            )

            print("👆 Touch the YubiKey to create credential with hmac-secret...")
            let response = try await session.makeCredential(parameters: params).value

            if let result = try hmacSecret.makeCredential.output(from: response) {
                switch result {
                case .enabled:
                    print("✅ HmacSecret enabled")
                case .secrets:
                    Issue.record("Expected .enabled result, got .secrets")
                }
            } else {
                Issue.record("Expected hmac-secret response")
            }
        }
    }

    @Test("HmacSecret MC - Derive Secrets at Registration (CTAP2.2)")
    func testHmacSecretMCDeriveSecrets() async throws {
        try await withCTAP2Session { session in
            let info = try await session.getInfo()

            // hmac-secret-mc requires a device that supports CTAP 2.3+
            guard info.extensions.contains(.hmacSecretMC) else {
                print("Device doesn't support hmac-secret-mc - skipping")
                return
            }

            // Need PIN for hmac-secret-mc
            guard info.options.clientPin == true else {
                print("PIN not set - skipping hmac-secret-mc test")
                return
            }

            let clientDataHash = Data(repeating: 0xCD, count: 32)
            let salt1 = Data(repeating: 0xAA, count: 32)
            let salt2 = Data(repeating: 0xBB, count: 32)

            let hmacSecret = try await CTAP2.Extension.HmacSecret(session: session)
            let hmacSecretInput = try hmacSecret.makeCredential.input(salt1: salt1, salt2: salt2)

            let pinToken = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.makeCredential],
                rpId: "hmac-secret-mc-test.com"
            )

            let params = CTAP2.MakeCredential.Parameters(
                clientDataHash: clientDataHash,
                rp: WebAuthn.PublicKeyCredential.RPEntity(id: "hmac-secret-mc-test.com", name: "HmacSecretMC Test"),
                user: WebAuthn.PublicKeyCredential.UserEntity(
                    id: Data(repeating: 0x20, count: 32),
                    name: "hmac-mc@test.com",
                    displayName: "HmacSecretMC User"
                ),
                pubKeyCredParams: [.es256],
                extensions: [hmacSecretInput],
                options: .init(rk: true)
            )

            print("👆 Touch the YubiKey to create credential with hmac-secret-mc...")
            let response = try await session.makeCredential(parameters: params, pinToken: pinToken).value

            if let result = try hmacSecret.makeCredential.output(from: response) {
                switch result {
                case .enabled:
                    Issue.record("Expected .secrets result, got .enabled")
                case .secrets(let secrets):
                    #expect(secrets.first.count == 32)
                    #expect(secrets.second?.count == 32)
                    print("✅ HmacSecretMC derived secrets:")
                    let first = secrets.first.prefix(8).map { String(format: "%02x", $0) }.joined()
                    let second = secrets.second?.prefix(8).map { String(format: "%02x", $0) }.joined()
                    print("   first: \(first)...")
                    print("   second: \(second ?? "nil")...")
                }
            } else {
                Issue.record("Expected hmac-secret-mc response")
            }
        }
    }
}
