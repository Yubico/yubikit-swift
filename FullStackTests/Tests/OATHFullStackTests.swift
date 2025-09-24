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

@Suite("OATH Full Stack Tests", .serialized)
struct OATHFullStackTests {

    // MARK: - Code Calculation Tests

    @Test("Calculate codes with large response data")
    func readChunkedData() async throws {
        try await runOATHTest { session in
            for n in 0...14 {
                let secret = "abba".base32DecodedData!
                let credentialOne = OATHSession.CredentialTemplate(
                    type: .totp(),
                    algorithm: .sha1,
                    secret: secret,
                    issuer: "Yubico-\(n)",
                    name: "test@yubico.com",
                    digits: 6
                )
                try await session.addCredential(template: credentialOne)
            }
            let result = try await session.calculateCredentialCodes()
            #expect(result.count == 20)
            trace("\(result)")
        }
    }

    // MARK: - Credential Management Tests

    @Test("List credentials")
    func listCredentials() async throws {
        try await runOATHTest { session in
            let credentials = try await session.listCredentials()
            #expect(credentials.count == 5)
            #expect(credentials[0].label == "TOTP SHA1:6 digits, 30 sec")
            #expect(credentials[0].type.period == 30.0)
            #expect(credentials[1].label == "TOTP SHA256:6 digits, 30 sec")
            #expect(credentials[2].type.period == 15.0)
            #expect(credentials[2].label == "15/TOTP SHA1 15s no issuer")
            #expect(credentials[3].label == "TOTP SHA256:requires touch, 6 digits, 30 sec")
            #expect(credentials[4].label == "HOTP SHA1:6 digits, counter = 0")
            #expect(credentials[4].type.counter == 0)
        }
    }

    @Test("Calculate all codes including touch required")
    func calculateAllCodes() async throws {
        try await runOATHTest { session in
            let result = try await session.calculateCredentialCodes(timestamp: Date(timeIntervalSince1970: 0))
            var codes: [OATHSession.Code] = []
            for pair in result {
                if let code = pair.1 {
                    codes.append(code)
                } else {
                    let credential = pair.0
                    if credential.requiresTouch {
                        trace("Touch the YubiKey!")
                    }
                    let code = try await session.calculateCredentialCode(
                        for: credential,
                        timestamp: Date(timeIntervalSince1970: 0)
                    )
                    codes.append(code)
                }
            }
            #expect(codes.count == 5)
            #expect(codes[0].code == "659165")
            #expect(codes[1].code == "807284")
            #expect(codes[2].code == "29659165")
            #expect(codes[3].code == "807284")
            #expect(codes[4].code == "659165")
        }
    }

    @Test("Calculate codes (non-touch only)")
    func calculateCodes() async throws {
        try await runOATHTest { session in
            let result = try await session.calculateCredentialCodes(timestamp: Date(timeIntervalSince1970: 0))
            let codes = result.map { $0.1?.code }.compactMap { $0 }
            #expect(codes.count == 3, "Too many codes. Might have calculated code that requires touch or a HOTP code.")
            #expect(codes[0] == "659165")
            #expect(codes[1] == "807284")
            #expect(codes[2] == "29659165")
        }
    }

    @Test("Calculate HMAC challenge response")
    func calculateResponse() async throws {
        try await runOATHTest { session in
            // Test data from rfc2202
            let secret = base32Encode(
                Data([
                    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                    0x0b, 0x0b, 0x0b, 0x0b,
                ])
            )
            let url = URL(
                string:
                    "otpauth://totp/Yubico:test@yubico.com?secret=\(secret)&issuer=test-create-and-calculate-response&algorithm=SHA1&digits=7&counter=30"
            )!
            let template = try! OATHSession.CredentialTemplate(url: url)
            let credential = try await session.addCredential(template: template)
            let response = try await session.calculateCredentialResponse(
                for: credential.id,
                challenge: Data("Hi There".utf8)
            )
            let expected = Data([
                0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2, 0x8b, 0xc0, 0xb6, 0xfb, 0x37, 0x8c, 0x8e, 0xf1,
                0x46, 0xbe, 0x00,
            ])
            #expect(response == expected)
        }
    }

    @Test("Add credential with numeric name prefix")
    func credentialsBeginningWithNumbers() async throws {
        try await runOATHTest(populated: false) { session in
            let template = OATHSession.CredentialTemplate(
                type: .totp(),
                algorithm: .sha1,
                secret: "abba2".base32DecodedData!,
                issuer: "15 Issuer",
                name: "15 begin with numbers",
                digits: 6
            )
            try await session.addCredential(template: template)
            let list = try await session.listCredentials()
            let credential = try #require(list.first, "Failed to add credential")
            let code = try await session.calculateCredentialCode(for: credential)
            trace("Got code: \(code.code)")
            #expect(!code.code.isEmpty)
        }
    }

    // MARK: - Security Tests

    // This will also test setPassword
    @Test("Unlock with password")
    func unlockWithPassword() async throws {
        try await runOATHTest(password: "password") { session in
            try await session.unlock(password: "password")
            let credentials = try await session.listCredentials()
            #expect(credentials.count == 5)
        }
    }

    @Test("Unlock with wrong password")
    func unlockWithWrongPassword() async throws {
        try await runOATHTest(password: "password") { session in
            do {
                try await session.unlock(password: "abc123")
            } catch {
                if case OATHSessionError.wrongPassword = error {
                    trace("Got expected error: \(error)")
                } else {
                    Issue.record("Got unexpected error: \(error)")
                }
            }
        }
    }

    @Test("Rename credential")
    func renameCredential() async throws {
        try await runOATHTest(populated: false) { session in
            let template = OATHSession.CredentialTemplate(
                type: .totp(),
                algorithm: .sha1,
                secret: "abba".base32DecodedData!,
                issuer: "Original Issuer",
                name: "Original Name",
                digits: 6
            )
            try await session.addCredential(template: template)
            guard let credential = try await session.listCredentials().first else {
                Issue.record("Failed adding credential to YubiKey.")
                return
            }
            do {
                try await session.renameCredential(credential, newName: "New Name", newIssuer: "New Issuer")
                guard let renamedCredential = try await session.listCredentials().first else {
                    Issue.record("Failed reading renamed credential from YubiKey.")
                    return
                }
                #expect(renamedCredential.name == "New Name")
                #expect(renamedCredential.issuer == "New Issuer")
            } catch {
                guard let error = error as? SessionError, error == .notSupported else {
                    Issue.record("Unexpected error: \(error)")
                    return
                }
                reportSkip(reason: "Feature not supported")
            }
        }
    }

    @Test("Rename credential with no issuer")
    func renameCredentialNoIssuer() async throws {
        try await runOATHTest(populated: false) { session in
            let template = OATHSession.CredentialTemplate(
                type: .totp(),
                algorithm: .sha1,
                secret: "abba".base32DecodedData!,
                issuer: "Original Issuer",
                name: "Original Name",
                digits: 6
            )
            try await session.addCredential(template: template)
            guard let credential = try await session.listCredentials().first else {
                Issue.record("Failed adding credential to YubiKey.")
                return
            }
            do {
                try await session.renameCredential(credential, newName: "New Name", newIssuer: nil)
                guard let renamedCredential = try await session.listCredentials().first else {
                    Issue.record("Failed reading renamed credential from YubiKey.")
                    return
                }
                #expect(renamedCredential.name == "New Name")
                #expect(renamedCredential.issuer == nil)
            } catch {
                guard let error = error as? SessionError, error == .notSupported else {
                    Issue.record("Unexpected error: \(error)")
                    return
                }
                reportSkip(reason: "Feature not supported")
            }
        }
    }

    @Test("Delete credential")
    func deleteCredential() async throws {
        try await runOATHTest { session in
            let credentials = try await session.listCredentials()
            try await session.deleteCredential(credentials.first!)
            let credentialsMinusOne = try await session.listCredentials()
            #expect(credentials.count == credentialsMinusOne.count + 1)
        }
    }

    // MARK: - Feature Tests

    @Test("Add SHA512 credential")
    func sha512Feature() async throws {
        try await runOATHTest(populated: false) { session in
            let template = OATHSession.CredentialTemplate(
                type: .totp(),
                algorithm: .sha512,
                secret: "abba2".base32DecodedData!,
                issuer: "SHA-512",
                name: "FeatureTest"
            )
            do {
                try await session.addCredential(template: template)
                guard let credential = try await session.listCredentials().first else {
                    Issue.record("Failed adding SHA512 credential.")
                    return
                }
                #expect(credential.hashAlgorithm! == .sha512)
                #expect(String(data: credential.id, encoding: .utf8) == template.identifier)
            } catch {
                guard let error = error as? SessionError, error == .notSupported else {
                    Issue.record("Unexpected error: \(error)")
                    return
                }
                reportSkip(reason: "Feature not supported")
            }
        }
    }

    @Test("Add touch-required credential")
    func touchFeature() async throws {
        try await runOATHTest(populated: false) { session in
            do {
                let touchTemplate = OATHSession.CredentialTemplate(
                    type: .totp(),
                    algorithm: .sha256,
                    secret: "abba2".base32DecodedData!,
                    issuer: "Touch",
                    name: "FeatureTest",
                    requiresTouch: true
                )
                try await session.addCredential(template: touchTemplate)
                guard let touchCredential = try await session.calculateCredentialCodes().first else {
                    Issue.record("Failed adding touch required credential.")
                    return
                }
                #expect(String(data: touchCredential.0.id, encoding: .utf8) == touchTemplate.identifier)
                #expect(touchCredential.0.requiresTouch)
                #expect(touchCredential.1 == nil)
                try await session.deleteCredential(touchCredential.0)
                let noTouchTemplate = OATHSession.CredentialTemplate(
                    type: .totp(),
                    algorithm: .sha256,
                    secret: "abba2".base32DecodedData!,
                    issuer: "Touch",
                    name: "FeatureTest",
                    requiresTouch: false
                )
                try await session.addCredential(template: noTouchTemplate)
                guard let noTouchCredential = try await session.calculateCredentialCodes().first else {
                    Issue.record("Failed adding no touch required credential.")
                    return
                }
                #expect(String(data: noTouchCredential.0.id, encoding: .utf8) == noTouchTemplate.identifier)
                #expect(noTouchCredential.1 != nil)
                #expect(!noTouchCredential.0.requiresTouch)
            } catch {
                guard let error = error as? SessionError, error == .notSupported else {
                    Issue.record("Unexpected error: \(error)")
                    return
                }
                reportSkip(reason: "Feature not supported")
            }
        }
    }

    @Test("Delete access key")
    func deleteAccessKey() async throws {
        try await runOATHTest(password: "password") { session in
            do {
                try await session.unlock(password: "password")
                try await session.deleteAccessKey()
                let connection = try await TestableConnection.shared()
                let _ = try await ManagementSession.makeSession(connection: connection)
                let session = try await OATHSession.makeSession(connection: connection)
                let credentials = try await session.listCredentials()
                #expect(credentials.count == 5)
            }
        }
    }

    @Test("Reset OATH application")
    func resetOATHApplication() async throws {
        try await runOATHTest { session in
            trace("Reset OATH application with test accounts and no password.")
        }
    }
}

// MARK: - Helpers

private func runOATHTest(
    populated: Bool = true,
    password: String? = nil,
    test: (OATHSession) async throws -> Void
) async throws {
    let connection = try await TestableConnection.shared()
    var session = try await OATHSession.makeSession(connection: connection)
    try await session.reset()
    session = try await OATHSession.makeSession(connection: connection)
    if populated {
        let secret = "abba".base32DecodedData!
        let credentialOne = OATHSession.CredentialTemplate(
            type: .totp(),
            algorithm: .sha1,
            secret: secret,
            issuer: "TOTP SHA1",
            name: "6 digits, 30 sec",
            digits: 6
        )
        try await session.addCredential(template: credentialOne)
        let credentialTwo = OATHSession.CredentialTemplate(
            type: .totp(),
            algorithm: .sha256,
            secret: secret,
            issuer: "TOTP SHA256",
            name: "6 digits, 30 sec",
            digits: 6
        )
        try await session.addCredential(template: credentialTwo)
        let credentialThree = OATHSession.CredentialTemplate(
            type: .totp(period: 15),
            algorithm: .sha1,
            secret: secret,
            issuer: nil,
            name: "15/TOTP SHA1 15s no issuer",
            digits: 8
        )
        try await session.addCredential(template: credentialThree)
        let credentialFour = OATHSession.CredentialTemplate(
            type: .totp(),
            algorithm: .sha256,
            secret: secret,
            issuer: "TOTP SHA256",
            name: "requires touch, 6 digits, 30 sec",
            digits: 6,
            requiresTouch: true
        )
        try await session.addCredential(template: credentialFour)
        let credentialFive = OATHSession.CredentialTemplate(
            type: .hotp(),
            algorithm: .sha1,
            secret: secret,
            issuer: "HOTP SHA1",
            name: "6 digits, counter = 0",
            digits: 6
        )
        try await session.addCredential(template: credentialFive)
    }

    if let password {
        try await session.setPassword(password)
        let _ = try await ManagementSession.makeSession(connection: connection)
        session = try await OATHSession.makeSession(connection: connection)
    }

    try await test(session)
}
