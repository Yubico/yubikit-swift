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

import XCTest

@testable import YubiKit

class OATHFullStackTests: XCTestCase {

    func testReadChunkedData() throws {
        runOATHTest { session in
            for n in 0...14 {
                let secret = "abba".base32DecodedData!
                let credentialOne = OATHSession.CredentialTemplate(
                    type: .TOTP(),
                    algorithm: .SHA1,
                    secret: secret,
                    issuer: "Yubico-\(n)",
                    name: "test@yubico.com",
                    digits: 6
                )
                try await session.addCredential(template: credentialOne)
            }
            let result = try await session.calculateCodes()
            XCTAssert(result.count == 20)
            print(result)
        }
    }

    func testListCredentials() throws {
        runOATHTest { session in
            let credentials = try await session.listCredentials()
            XCTAssert(credentials.count == 5)
            XCTAssert(credentials[0].label == "TOTP SHA1:6 digits, 30 sec")
            XCTAssert(credentials[0].type.period == 30.0)
            XCTAssert(credentials[1].label == "TOTP SHA256:6 digits, 30 sec")
            XCTAssert(credentials[2].type.period == 15.0)
            XCTAssert(credentials[2].label == "15/TOTP SHA1 15s no issuer")
            XCTAssert(credentials[3].label == "TOTP SHA256:requires touch, 6 digits, 30 sec")
            XCTAssert(credentials[4].label == "HOTP SHA1:6 digits, counter = 0")
            XCTAssert(credentials[4].type.counter == 0)
        }
    }

    func testCalculateAllCodes() throws {
        runOATHTest { session in
            let result = try await session.calculateCodes(timestamp: Date(timeIntervalSince1970: 0))
            let codes = try await result.asyncMap { result in
                if let code = result.1 {
                    return code
                }
                let credential = result.0
                if credential.requiresTouch {
                    print("👆 Touch the YubiKey!")
                }
                let code = try await session.calculateCode(
                    credential: credential,
                    timestamp: Date(timeIntervalSince1970: 0)
                )
                return code
            }
            XCTAssert(codes.count == 5)
            XCTAssert(codes[0].code == "659165")
            XCTAssert(codes[1].code == "807284")
            XCTAssert(codes[2].code == "29659165")
            XCTAssert(codes[3].code == "807284")
            XCTAssert(codes[4].code == "659165")
        }
    }

    func testCalculateCodes() throws {
        runOATHTest { session in
            let result = try await session.calculateCodes(timestamp: Date(timeIntervalSince1970: 0))
            let codes = result.map { $0.1?.code }.compactMap { $0 }
            XCTAssert(codes.count == 3, "To many codes. Might have calculated code that requires touch or a HOTP code.")
            XCTAssert(codes[0] == "659165")
            XCTAssert(codes[1] == "807284")
            XCTAssert(codes[2] == "29659165")
        }
    }

    func testCalculateResponse() throws {
        runOATHTest { session in
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
            let template = try! OATHSession.CredentialTemplate(withURL: url)
            let credential = try await session.addCredential(template: template)
            let response = try await session.calculateResponse(
                credentialId: credential.id,
                challenge: Data("Hi There".utf8)
            )
            let expected = Data([
                0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2, 0x8b, 0xc0, 0xb6, 0xfb, 0x37, 0x8c, 0x8e, 0xf1,
                0x46, 0xbe, 0x00,
            ])
            XCTAssertEqual(response, expected)
        }
    }

    func testCredentialsBeginningWithNumbers() throws {
        runOATHTest(populated: false) { session in
            let template = OATHSession.CredentialTemplate(
                type: .TOTP(),
                algorithm: .SHA1,
                secret: "abba2".base32DecodedData!,
                issuer: "15 Issuer",
                name: "15 begin with numbers",
                digits: 6
            )
            try await session.addCredential(template: template)
            let list = try await session.listCredentials()
            let credential = try XCTUnwrap(list.first, "Failed to add credential")
            let code = try await session.calculateCode(credential: credential)
            print("Got code: \(code.code)")
            XCTAssertNotNil(code.code)
        }
    }

    // This will also test setPassword
    func testUnlockWithPassword() throws {
        runOATHTest(password: "password") { session in
            try await session.unlockWithPassword("password")
            let credentials = try await session.listCredentials()
            XCTAssert(credentials.count == 5)
        }
    }

    func testUnlockWithWrongPassword() throws {
        runOATHTest(password: "password") { session in
            do {
                try await session.unlockWithPassword("abc123")
            } catch {
                if case OATHSessionError.wrongPassword = error {
                    print("Got expected error: \(error)")
                } else {
                    XCTFail("Got unexpected error: \(error)")
                }
            }
        }
    }

    func testRenameCredential() throws {
        runOATHTest(populated: false) { session in
            let template = OATHSession.CredentialTemplate(
                type: .TOTP(),
                algorithm: .SHA1,
                secret: "abba".base32DecodedData!,
                issuer: "Original Issuer",
                name: "Original Name",
                digits: 6
            )
            try await session.addCredential(template: template)
            guard let credential = try await session.listCredentials().first else {
                XCTFail("Failed adding credential to YubiKey.")
                return
            }
            do {
                try await session.renameCredential(credential, newName: "New Name", newIssuer: "New Issuer")
                guard let renamedCredential = try await session.listCredentials().first else {
                    XCTFail("Failed reading renamed credential from YubiKey.")
                    return
                }
                XCTAssertEqual(renamedCredential.name, "New Name")
                XCTAssertEqual(renamedCredential.issuer, "New Issuer")
            } catch {
                guard let error = error as? SessionError, error == .notSupported else {
                    XCTFail("Unexpected error: \(error)")
                    return
                }
                print("⚠️ Skip testRenameCredential()")
            }
        }
    }

    func testRenameCredentialNoIssuer() throws {
        runOATHTest(populated: false) { session in
            let template = OATHSession.CredentialTemplate(
                type: .TOTP(),
                algorithm: .SHA1,
                secret: "abba".base32DecodedData!,
                issuer: "Original Issuer",
                name: "Original Name",
                digits: 6
            )
            try await session.addCredential(template: template)
            guard let credential = try await session.listCredentials().first else {
                XCTFail("Failed adding credential to YubiKey.")
                return
            }
            do {
                try await session.renameCredential(credential, newName: "New Name", newIssuer: nil)
                guard let renamedCredential = try await session.listCredentials().first else {
                    XCTFail("Failed reading renamed credential from YubiKey.")
                    return
                }
                XCTAssertEqual(renamedCredential.name, "New Name")
                XCTAssertNil(renamedCredential.issuer)
            } catch {
                guard let error = error as? SessionError, error == .notSupported else {
                    XCTFail("Unexpected error: \(error)")
                    return
                }
                print("⚠️ Skip testRenameCredentialNoIssuer()")
            }
        }
    }

    func testDeleteCredential() throws {
        runOATHTest { session in
            let credentials = try await session.listCredentials()
            try await session.deleteCredential(credentials.first!)
            let credentialsMinusOne = try await session.listCredentials()
            XCTAssertEqual(credentials.count, credentialsMinusOne.count + 1)
        }
    }

    func testSHA512Feature() throws {
        runOATHTest(populated: false) { session in
            let template = OATHSession.CredentialTemplate(
                type: .TOTP(),
                algorithm: .SHA512,
                secret: "abba2".base32DecodedData!,
                issuer: "SHA-512",
                name: "FeatureTest"
            )
            do {
                try await session.addCredential(template: template)
                guard let credential = try await session.listCredentials().first else {
                    XCTFail("Failed adding SHA512 credential.")
                    return
                }
                XCTAssertEqual(credential.hashAlgorithm!, .SHA512)
                XCTAssertEqual(String(data: credential.id, encoding: .utf8), template.identifier)
            } catch {
                guard let error = error as? SessionError, error == .notSupported else {
                    XCTFail("Unexpected error: \(error)")
                    return
                }
                print("⚠️ Skip testSHA512Feature()")
            }
        }
    }

    func testTouchFeature() throws {
        runOATHTest(populated: false) { session in
            do {
                let touchTemplate = OATHSession.CredentialTemplate(
                    type: .TOTP(),
                    algorithm: .SHA256,
                    secret: "abba2".base32DecodedData!,
                    issuer: "Touch",
                    name: "FeatureTest",
                    requiresTouch: true
                )
                try await session.addCredential(template: touchTemplate)
                guard let touchCredential = try await session.calculateCodes().first else {
                    XCTFail("Failed adding touch required credential.")
                    return
                }
                XCTAssertEqual(String(data: touchCredential.0.id, encoding: .utf8), touchTemplate.identifier)
                XCTAssertTrue(touchCredential.0.requiresTouch)
                XCTAssertNil(touchCredential.1)
                try await session.deleteCredential(touchCredential.0)
                let noTouchTemplate = OATHSession.CredentialTemplate(
                    type: .TOTP(),
                    algorithm: .SHA256,
                    secret: "abba2".base32DecodedData!,
                    issuer: "Touch",
                    name: "FeatureTest",
                    requiresTouch: false
                )
                try await session.addCredential(template: noTouchTemplate)
                guard let noTouchCredential = try await session.calculateCodes().first else {
                    XCTFail("Failed adding no touch required credential.")
                    return
                }
                XCTAssertEqual(String(data: noTouchCredential.0.id, encoding: .utf8), noTouchTemplate.identifier)
                XCTAssertNotNil(noTouchCredential.1)
                XCTAssertFalse(noTouchCredential.0.requiresTouch)
            } catch {
                guard let error = error as? SessionError, error == .notSupported else {
                    XCTFail("Unexpected error: \(error)")
                    return
                }
                print("⚠️ Skip testTouchFeature()")
            }
        }
    }

    func testDeleteAccessKey() throws {
        runOATHTest(password: "password") { session in
            do {
                try await session.unlockWithPassword("password")
                try await session.deleteAccessKey()
                let connection = try await AllowedConnections.anyConnection()
                let _ = try await ManagementSession.session(withConnection: connection)
                let session = try await OATHSession.session(withConnection: connection)
                let credentials = try await session.listCredentials()
                XCTAssertEqual(credentials.count, 5)
            }
        }
    }

    func testZeLastOne() throws {
        runOATHTest { session in
            print("Reset OATH application with test accounts and no password.")
        }
    }
}

extension XCTestCase {
    func runOATHTest(
        populated: Bool = true,
        password: String? = nil,
        named testName: String = #function,
        in file: StaticString = #file,
        at line: UInt = #line,
        withTimeout timeout: TimeInterval = 20,
        test: @escaping (OATHSession) async throws -> Void
    ) {
        runAsyncTest(named: testName, in: file, at: line, withTimeout: timeout) {
            let connection = try await AllowedConnections.anyConnection()
            var session = try await OATHSession.session(withConnection: connection)
            try await session.reset()
            session = try await OATHSession.session(withConnection: connection)
            if populated {
                let secret = "abba".base32DecodedData!
                let credentialOne = OATHSession.CredentialTemplate(
                    type: .TOTP(),
                    algorithm: .SHA1,
                    secret: secret,
                    issuer: "TOTP SHA1",
                    name: "6 digits, 30 sec",
                    digits: 6
                )
                try await session.addCredential(template: credentialOne)
                let credentialTwo = OATHSession.CredentialTemplate(
                    type: .TOTP(),
                    algorithm: .SHA256,
                    secret: secret,
                    issuer: "TOTP SHA256",
                    name: "6 digits, 30 sec",
                    digits: 6
                )
                try await session.addCredential(template: credentialTwo)
                let credentialThree = OATHSession.CredentialTemplate(
                    type: .TOTP(period: 15),
                    algorithm: .SHA1,
                    secret: secret,
                    issuer: nil,
                    name: "TOTP SHA1 15s no issuer",
                    digits: 8
                )
                try await session.addCredential(template: credentialThree)
                let credentialFour = OATHSession.CredentialTemplate(
                    type: .TOTP(),
                    algorithm: .SHA256,
                    secret: secret,
                    issuer: "TOTP SHA256",
                    name: "requires touch, 6 digits, 30 sec",
                    digits: 6,
                    requiresTouch: true
                )
                try await session.addCredential(template: credentialFour)
                let credentialFive = OATHSession.CredentialTemplate(
                    type: .HOTP(),
                    algorithm: .SHA1,
                    secret: secret,
                    issuer: "HOTP SHA1",
                    name: "6 digits, counter = 0",
                    digits: 6
                )
                try await session.addCredential(template: credentialFive)
            }

            if let password {
                try await session.setPassword(password)
                let _ = try await ManagementSession.session(withConnection: connection)
                session = try await OATHSession.session(withConnection: connection)
            }

            try await test(session)
        }
    }
}
