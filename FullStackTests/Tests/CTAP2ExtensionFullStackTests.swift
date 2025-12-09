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

@testable import FullStackTests
@testable import YubiKit

@Suite("CTAP2 Extension Full Stack Tests", .serialized)
struct CTAP2ExtensionFullStackTests {

    private let testPin = "11234567"

    // MARK: - CredProtect Extension Tests

    @Test("CredProtect - Level 1 (User Verification Optional)")
    func testCredProtectLevel1() async throws {
        try await withCTAP2Session { session in
            // Check if credProtect is supported
            guard try await CTAP2.Extension.CredProtect.isSupported(by: session) else {
                print("Device doesn't support credProtect - skipping")
                return
            }

            let clientDataHash = Data(repeating: 0xCD, count: 32)
            let credProtect = CTAP2.Extension.CredProtect(level: .userVerificationOptional)

            let params = CTAP2.MakeCredential.Parameters(
                clientDataHash: clientDataHash,
                rp: PublicKeyCredential.RPEntity(id: "credprotect-test.com", name: "CredProtect Test"),
                user: PublicKeyCredential.UserEntity(
                    id: Data(repeating: 0x01, count: 32),
                    name: "level1@test.com",
                    displayName: "Level 1 User"
                ),
                pubKeyCredParams: [.es256],
                options: .init(rk: false),
                extensions: [credProtect]
            )

            print("👆 Touch the YubiKey to create credential with credProtect level 1...")
            let response = try await session.makeCredential(parameters: params).value

            // Check credProtect result
            if let result = credProtect.result(from: response) {
                #expect(result.level == .userVerificationOptional)
                print("✅ CredProtect level 1 confirmed: \(result.level)")
            } else {
                // Some authenticators may not echo back the extension if it's the default
                print("✅ Credential created (authenticator didn't echo credProtect - level 1 is default)")
            }
        }
    }

    @Test("CredProtect - Level 2 (UV Optional with Credential ID List)")
    func testCredProtectLevel2() async throws {
        try await withCTAP2Session { session in
            guard try await CTAP2.Extension.CredProtect.isSupported(by: session) else {
                print("Device doesn't support credProtect - skipping")
                return
            }

            let clientDataHash = Data(repeating: 0xCD, count: 32)
            let credProtect = CTAP2.Extension.CredProtect(level: .userVerificationOptionalWithCredentialIDList)

            let params = CTAP2.MakeCredential.Parameters(
                clientDataHash: clientDataHash,
                rp: PublicKeyCredential.RPEntity(id: "credprotect-test.com", name: "CredProtect Test"),
                user: PublicKeyCredential.UserEntity(
                    id: Data(repeating: 0x02, count: 32),
                    name: "level2@test.com",
                    displayName: "Level 2 User"
                ),
                pubKeyCredParams: [.es256],
                options: .init(rk: true),  // Discoverable credential
                extensions: [credProtect]
            )

            print("👆 Touch the YubiKey to create credential with credProtect level 2...")
            let response = try await session.makeCredential(parameters: params).value

            if let result = credProtect.result(from: response) {
                #expect(result.level == .userVerificationOptionalWithCredentialIDList)
                print("✅ CredProtect level 2 confirmed: \(result.level)")
            } else {
                Issue.record("Expected credProtect level 2 in response")
            }
        }
    }

    @Test("CredProtect - Level 3 (UV Required)")
    func testCredProtectLevel3() async throws {
        try await withCTAP2Session { session in
            guard try await CTAP2.Extension.CredProtect.isSupported(by: session) else {
                print("Device doesn't support credProtect - skipping")
                return
            }

            let clientDataHash = Data(repeating: 0xCD, count: 32)
            let credProtect = CTAP2.Extension.CredProtect(level: .userVerificationRequired)

            let params = CTAP2.MakeCredential.Parameters(
                clientDataHash: clientDataHash,
                rp: PublicKeyCredential.RPEntity(id: "credprotect-test.com", name: "CredProtect Test"),
                user: PublicKeyCredential.UserEntity(
                    id: Data(repeating: 0x03, count: 32),
                    name: "level3@test.com",
                    displayName: "Level 3 User"
                ),
                pubKeyCredParams: [.es256],
                options: .init(rk: true),  // Discoverable credential
                extensions: [credProtect]
            )

            print("👆 Touch the YubiKey to create credential with credProtect level 3...")
            let response = try await session.makeCredential(parameters: params).value

            if let result = credProtect.result(from: response) {
                #expect(result.level == .userVerificationRequired)
                print("✅ CredProtect level 3 confirmed: \(result.level)")
            } else {
                Issue.record("Expected credProtect level 3 in response")
            }
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
            let hmacSecret = CTAP2.Extension.HmacSecret.makeCredential()

            let params = CTAP2.MakeCredential.Parameters(
                clientDataHash: clientDataHash,
                rp: PublicKeyCredential.RPEntity(id: "hmac-secret-test.com", name: "HmacSecret Test"),
                user: PublicKeyCredential.UserEntity(
                    id: Data(repeating: 0x10, count: 32),
                    name: "hmac@test.com",
                    displayName: "HmacSecret User"
                ),
                pubKeyCredParams: [.es256],
                options: .init(rk: true),
                extensions: [hmacSecret]
            )

            print("👆 Touch the YubiKey to create credential with hmac-secret...")
            let response = try await session.makeCredential(parameters: params).value

            if let result = try hmacSecret.result(from: response) {
                switch result {
                case .enabled(let enabled):
                    #expect(enabled == true)
                    print("✅ HmacSecret enabled: \(enabled)")
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

            // hmac-secret-mc requires CTAP 2.2
            guard info.extensions.contains(CTAP2.Extension.HmacSecret.mcIdentifier) else {
                print("Device doesn't support hmac-secret-mc (CTAP2.2) - skipping")
                return
            }

            // Need PIN for hmac-secret-mc
            guard info.options.clientPin == true else {
                print("PIN not set - skipping hmac-secret-mc test")
                return
            }

            // Get PIN token
            let pinToken = try await session.getPinUVToken(
                using: .pin(testPin),
                permissions: [.makeCredential],
                rpId: "hmac-secret-mc-test.com"
            )

            let clientDataHash = Data(repeating: 0xCD, count: 32)
            let salt1 = Data(repeating: 0xAA, count: 32)
            let salt2 = Data(repeating: 0xBB, count: 32)

            let hmacSecretMC = try await CTAP2.Extension.HmacSecret.makeCredential(
                salt1: salt1,
                salt2: salt2,
                session: session
            )

            let params = CTAP2.MakeCredential.Parameters(
                clientDataHash: clientDataHash,
                rp: PublicKeyCredential.RPEntity(id: "hmac-secret-mc-test.com", name: "HmacSecretMC Test"),
                user: PublicKeyCredential.UserEntity(
                    id: Data(repeating: 0x20, count: 32),
                    name: "hmac-mc@test.com",
                    displayName: "HmacSecretMC User"
                ),
                pubKeyCredParams: [.es256],
                options: .init(rk: true, uv: true),
                extensions: [hmacSecretMC]
            )

            print("👆 Touch the YubiKey to create credential with hmac-secret-mc...")
            let response = try await session.makeCredential(parameters: params, pinToken: pinToken).value

            if let result = try hmacSecretMC.result(from: response) {
                switch result {
                case .enabled:
                    Issue.record("Expected .secrets result, got .enabled")
                case .secrets(let output1, let output2):
                    #expect(output1.count == 32)
                    #expect(output2?.count == 32)
                    print("✅ HmacSecretMC derived secrets:")
                    print("   output1: \(output1.prefix(8).map { String(format: "%02x", $0) }.joined())...")
                    print("   output2: \(output2?.prefix(8).map { String(format: "%02x", $0) }.joined() ?? "nil")...")
                }
            } else {
                Issue.record("Expected hmac-secret-mc response")
            }
        }
    }
}
