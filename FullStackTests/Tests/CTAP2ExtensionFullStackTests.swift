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
            guard info.extensions.contains("hmac-secret-mc") else {
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
                extensions: [hmacSecretMC],
                pinUVAuthParam: pinToken.authenticate(message: clientDataHash),
                pinUVAuthProtocol: pinToken.protocolVersion
            )

            print("👆 Touch the YubiKey to create credential with hmac-secret-mc...")
            let response = try await session.makeCredential(parameters: params).value

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

    // MARK: - HmacSecret GetAssertion Extension Tests

    @Test("HmacSecret - Derive Secrets at GetAssertion")
    func testHmacSecretGetAssertion() async throws {
        try await withCTAP2Session { session in
            guard try await CTAP2.Extension.HmacSecret.isSupported(by: session) else {
                print("Device doesn't support hmac-secret - skipping")
                return
            }

            let info = try await session.getInfo()
            guard info.options.clientPin == true else {
                print("PIN not set - skipping hmac-secret GetAssertion test")
                return
            }

            let rpId = "hmac-secret-ga-test.com"
            let clientDataHash = Data(repeating: 0xCD, count: 32)

            // 1. First create a credential with hmac-secret enabled
            let makeCredParams = CTAP2.MakeCredential.Parameters(
                clientDataHash: clientDataHash,
                rp: PublicKeyCredential.RPEntity(id: rpId, name: "HmacSecret GA Test"),
                user: PublicKeyCredential.UserEntity(
                    id: Data(repeating: 0x30, count: 32),
                    name: "hmac-ga@test.com",
                    displayName: "HmacSecret GA User"
                ),
                pubKeyCredParams: [.es256],
                options: .init(rk: true),
                extensions: [CTAP2.Extension.HmacSecret.makeCredential()]
            )

            print("👆 Touch the YubiKey to create credential with hmac-secret...")
            let makeCredResponse = try await session.makeCredential(parameters: makeCredParams).value

            guard let attestedData = makeCredResponse.authenticatorData.attestedCredentialData else {
                Issue.record("Missing attested credential data")
                return
            }
            let idPrefix = attestedData.credentialId.prefix(8).map { String(format: "%02x", $0) }.joined()
            print("✅ Credential created with ID: \(idPrefix)...")

            // 2. Now use GetAssertion with hmac-secret to derive secrets
            let salt1 = Data(repeating: 0xCC, count: 32)

            let hmacSecretGA = try await CTAP2.Extension.HmacSecret.getAssertion(
                salt1: salt1,
                session: session
            )

            // Need PIN token for hmac-secret in GetAssertion
            let pinToken = try await session.getPinUVToken(
                using: .pin(testPin),
                permissions: [.getAssertion],
                rpId: rpId
            )

            let getAssertionParams = CTAP2.GetAssertion.Parameters(
                rpId: rpId,
                clientDataHash: clientDataHash,
                allowList: [
                    PublicKeyCredential.Descriptor(
                        type: .publicKey,
                        id: attestedData.credentialId
                    )
                ],
                extensions: [hmacSecretGA],
                options: .init(up: true, uv: true),
                pinUVAuthParam: pinToken.authenticate(message: clientDataHash),
                pinUVAuthProtocol: pinToken.protocolVersion
            )

            print("👆 Touch the YubiKey to authenticate with hmac-secret...")
            let assertionResponse = try await session.getAssertion(parameters: getAssertionParams).value

            if let (output1, output2) = try hmacSecretGA.result(from: assertionResponse) {
                #expect(output1.count == 32)
                #expect(output2 == nil)  // We only provided salt1
                print("✅ HmacSecret GetAssertion derived secret:")
                print("   output1: \(output1.prefix(8).map { String(format: "%02x", $0) }.joined())...")
            } else {
                Issue.record("Expected hmac-secret response in GetAssertion")
            }
        }
    }

    @Test("HmacSecret - Derive Two Secrets at GetAssertion")
    func testHmacSecretGetAssertionTwoSalts() async throws {
        try await withCTAP2Session { session in
            guard try await CTAP2.Extension.HmacSecret.isSupported(by: session) else {
                print("Device doesn't support hmac-secret - skipping")
                return
            }

            let info = try await session.getInfo()
            guard info.options.clientPin == true else {
                print("PIN not set - skipping hmac-secret GetAssertion test")
                return
            }

            let rpId = "hmac-secret-ga2-test.com"
            let clientDataHash = Data(repeating: 0xCD, count: 32)

            // 1. First create a credential with hmac-secret enabled
            let makeCredParams = CTAP2.MakeCredential.Parameters(
                clientDataHash: clientDataHash,
                rp: PublicKeyCredential.RPEntity(id: rpId, name: "HmacSecret GA2 Test"),
                user: PublicKeyCredential.UserEntity(
                    id: Data(repeating: 0x40, count: 32),
                    name: "hmac-ga2@test.com",
                    displayName: "HmacSecret GA2 User"
                ),
                pubKeyCredParams: [.es256],
                options: .init(rk: true),
                extensions: [CTAP2.Extension.HmacSecret.makeCredential()]
            )

            print("👆 Touch the YubiKey to create credential with hmac-secret...")
            let makeCredResponse = try await session.makeCredential(parameters: makeCredParams).value

            guard let attestedData = makeCredResponse.authenticatorData.attestedCredentialData else {
                Issue.record("Missing attested credential data")
                return
            }
            print("✅ Credential created")

            // 2. Now use GetAssertion with two salts
            let salt1 = Data(repeating: 0xDD, count: 32)
            let salt2 = Data(repeating: 0xEE, count: 32)

            let hmacSecretGA = try await CTAP2.Extension.HmacSecret.getAssertion(
                salt1: salt1,
                salt2: salt2,
                session: session
            )

            let pinToken = try await session.getPinUVToken(
                using: .pin(testPin),
                permissions: [.getAssertion],
                rpId: rpId
            )

            let getAssertionParams = CTAP2.GetAssertion.Parameters(
                rpId: rpId,
                clientDataHash: clientDataHash,
                allowList: [
                    PublicKeyCredential.Descriptor(
                        type: .publicKey,
                        id: attestedData.credentialId
                    )
                ],
                extensions: [hmacSecretGA],
                options: .init(up: true, uv: true),
                pinUVAuthParam: pinToken.authenticate(message: clientDataHash),
                pinUVAuthProtocol: pinToken.protocolVersion
            )

            print("👆 Touch the YubiKey to authenticate with hmac-secret (two salts)...")
            let assertionResponse = try await session.getAssertion(parameters: getAssertionParams).value

            if let (output1, output2) = try hmacSecretGA.result(from: assertionResponse) {
                #expect(output1.count == 32)
                #expect(output2?.count == 32)
                #expect(output1 != output2)  // Different salts should produce different outputs
                print("✅ HmacSecret GetAssertion derived two secrets:")
                print("   output1: \(output1.prefix(8).map { String(format: "%02x", $0) }.joined())...")
                print("   output2: \(output2?.prefix(8).map { String(format: "%02x", $0) }.joined() ?? "nil")...")
            } else {
                Issue.record("Expected hmac-secret response in GetAssertion")
            }
        }
    }

    @Test("HmacSecret - Same Salt Produces Same Output (Deterministic)")
    func testHmacSecretDeterministic() async throws {
        try await withCTAP2Session { session in
            guard try await CTAP2.Extension.HmacSecret.isSupported(by: session) else {
                print("Device doesn't support hmac-secret - skipping")
                return
            }

            let info = try await session.getInfo()
            guard info.options.clientPin == true else {
                print("PIN not set - skipping hmac-secret determinism test")
                return
            }

            let rpId = "hmac-secret-deterministic-test.com"
            let clientDataHash = Data(repeating: 0xCD, count: 32)
            let fixedSalt = Data(repeating: 0xFF, count: 32)

            // 1. Create credential with hmac-secret
            let makeCredParams = CTAP2.MakeCredential.Parameters(
                clientDataHash: clientDataHash,
                rp: PublicKeyCredential.RPEntity(id: rpId, name: "HmacSecret Deterministic Test"),
                user: PublicKeyCredential.UserEntity(
                    id: Data(repeating: 0x50, count: 32),
                    name: "hmac-det@test.com",
                    displayName: "HmacSecret Deterministic User"
                ),
                pubKeyCredParams: [.es256],
                options: .init(rk: true),
                extensions: [CTAP2.Extension.HmacSecret.makeCredential()]
            )

            print("👆 Touch the YubiKey to create credential...")
            let makeCredResponse = try await session.makeCredential(parameters: makeCredParams).value

            guard let attestedData = makeCredResponse.authenticatorData.attestedCredentialData else {
                Issue.record("Missing attested credential data")
                return
            }
            print("✅ Credential created")

            // 2. Get first secret
            let hmacSecretGA1 = try await CTAP2.Extension.HmacSecret.getAssertion(
                salt1: fixedSalt,
                session: session
            )

            let pinToken1 = try await session.getPinUVToken(
                using: .pin(testPin),
                permissions: [.getAssertion],
                rpId: rpId
            )

            let getAssertionParams1 = CTAP2.GetAssertion.Parameters(
                rpId: rpId,
                clientDataHash: clientDataHash,
                allowList: [
                    PublicKeyCredential.Descriptor(type: .publicKey, id: attestedData.credentialId)
                ],
                extensions: [hmacSecretGA1],
                options: .init(up: true, uv: true),
                pinUVAuthParam: pinToken1.authenticate(message: clientDataHash),
                pinUVAuthProtocol: pinToken1.protocolVersion
            )

            print("👆 Touch the YubiKey (first assertion)...")
            let assertionResponse1 = try await session.getAssertion(parameters: getAssertionParams1).value
            let output1 = try hmacSecretGA1.result(from: assertionResponse1)?.output1
            guard let output1 else {
                Issue.record("Expected hmac-secret output in first assertion")
                return
            }

            // 3. Get second secret with same salt
            let hmacSecretGA2 = try await CTAP2.Extension.HmacSecret.getAssertion(
                salt1: fixedSalt,
                session: session
            )

            let pinToken2 = try await session.getPinUVToken(
                using: .pin(testPin),
                permissions: [.getAssertion],
                rpId: rpId
            )

            let getAssertionParams2 = CTAP2.GetAssertion.Parameters(
                rpId: rpId,
                clientDataHash: clientDataHash,
                allowList: [
                    PublicKeyCredential.Descriptor(type: .publicKey, id: attestedData.credentialId)
                ],
                extensions: [hmacSecretGA2],
                options: .init(up: true, uv: true),
                pinUVAuthParam: pinToken2.authenticate(message: clientDataHash),
                pinUVAuthProtocol: pinToken2.protocolVersion
            )

            print("👆 Touch the YubiKey (second assertion)...")
            let assertionResponse2 = try await session.getAssertion(parameters: getAssertionParams2).value
            let output2 = try hmacSecretGA2.result(from: assertionResponse2)?.output1
            guard let output2 else {
                Issue.record("Expected hmac-secret output in second assertion")
                return
            }

            // 4. Verify outputs are identical
            #expect(output1 == output2, "Same salt should produce same output")
            print("✅ HmacSecret is deterministic:")
            print("   output1: \(output1.map { String(format: "%02x", $0) }.joined())")
            print("   output2: \(output2.map { String(format: "%02x", $0) }.joined())")
        }
    }

    // MARK: - Helper Methods

    #if os(macOS)
    private func withCTAP2Session<T>(
        _ body: (FIDO2Session) async throws -> T
    ) async throws -> T {
        let connection = try await HIDFIDOConnection.makeConnection()
        let session = try await CTAP2.Session.makeSession(connection: connection)
        let result = try await body(session)
        await connection.close(error: nil)
        return result
    }

    #elseif os(iOS)
    private func withCTAP2Session<T>(
        _ body: (FIDO2SessionOverSmartCard) async throws -> T
    ) async throws -> T {
        let connection = try await TestableConnection.create(with: .nfc)
        let session = try await CTAP.Session.makeSession(connection: connection)
        let result = try await body(session)
        await connection.close(error: nil)
        return result
    }
    #endif
}
