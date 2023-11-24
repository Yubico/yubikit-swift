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
import YubiKit

@testable import FullStackTests

class OATHFullStackTests: XCTestCase {
    
    func testReadChunkedData() throws {
        runOATHTest { session in
            for n in 0...14 {
                let secret = "abba".base32DecodedData!
                let credentialOne = OATHSession.CredentialTemplate(type: .TOTP(), algorithm: .SHA1, secret: secret, issuer: "Yubico-\(n)", name: "test@yubico.com", digits: 6)
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
            XCTAssert(credentials[1].label == "TOTP SHA256:6 digits, 30 sec")
            XCTAssert(credentials[2].label == "TOTP SHA1 15s no issuer")
            XCTAssert(credentials[3].label == "TOTP SHA256:requires touch, 6 digits, 30 sec")
            XCTAssert(credentials[4].label == "HOTP SHA1:6 digits, counter = 0")
        }
    }
    
    func testListCredentialsAndCalculate() throws {
        runOATHTest { session in
            let credentials = try await session.listCredentials()
            let codes = try await credentials.asyncMap { credential in
                let code = try await session.calculateCode(credential: credential, timestamp: Date(timeIntervalSince1970: 0))
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
            let secret = base32Encode(Data([0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b]))
            let url = URL(string: "otpauth://totp/Yubico:test@yubico.com?secret=\(secret)&issuer=test-create-and-calculate-response&algorithm=SHA1&digits=7&counter=30")!
            let template = try! OATHSession.CredentialTemplate(withURL: url)
            let credential = try await session.addCredential(template: template)
            let response = try await session.calculateResponse(credentialId: credential.id, challenge: Data("Hi There".utf8))
            let expected = Data([0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2, 0x8b, 0xc0, 0xb6, 0xfb, 0x37, 0x8c, 0x8e, 0xf1, 0x46, 0xbe, 0x00])
            XCTAssertEqual(response, expected)
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
    
    func testDeleteCredential() throws {
        runOATHTest() { session in
            let credentials = try await session.listCredentials()
            try await session.deleteCredential(credentials.first!)
            let credentialsMinusOne = try await session.listCredentials()
            XCTAssertEqual(credentials.count, credentialsMinusOne.count + 1)
        }
    }
    
    func testDeleteAccessKey() throws {
        runOATHTest(password: "password") { session in
            do {
                try await session.unlockWithPassword("password")
                try await session.deleteAccessKey()
                let connection = try await ConnectionHelper.anyConnection()
                let _ = try await ManagementSession.session(withConnection: connection)
                let session = try await OATHSession.session(withConnection: connection)
                let credentials = try await session.listCredentials()
                XCTAssertEqual(credentials.count, 5)
            }
        }
    }
}


extension XCTestCase {
    func runOATHTest(populated: Bool = true,
                     password: String? = nil,
                     named testName: String = #function,
                     in file: StaticString = #file,
                     at line: UInt = #line,
                     withTimeout timeout: TimeInterval = 20,
                     test: @escaping (OATHSession) async throws -> Void) {
        runAsyncTest(named: testName, in: file, at: line, withTimeout: timeout) {
            let connection = try await ConnectionHelper.anyConnection()
            var session = try await OATHSession.session(withConnection: connection)
            try await session.reset()
            
            if populated {
                let secret = "abba".base32DecodedData!
                let credentialOne = OATHSession.CredentialTemplate(type: .TOTP(), algorithm: .SHA1, secret: secret, issuer: "TOTP SHA1", name: "6 digits, 30 sec", digits: 6)
                try await session.addCredential(template: credentialOne)
                let credentialTwo = OATHSession.CredentialTemplate(type: .TOTP(), algorithm: .SHA256, secret: secret, issuer: "TOTP SHA256", name: "6 digits, 30 sec", digits: 6)
                try await session.addCredential(template: credentialTwo)
                let credentialThree = OATHSession.CredentialTemplate(type: .TOTP(period: 15), algorithm: .SHA1, secret: secret, issuer: nil, name: "TOTP SHA1 15s no issuer", digits: 8)
                try await session.addCredential(template: credentialThree)
                let credentialFour = OATHSession.CredentialTemplate(type: .TOTP(), algorithm: .SHA256, secret: secret, issuer: "TOTP SHA256", name: "requires touch, 6 digits, 30 sec", digits: 6, requiresTouch: true)
                try await session.addCredential(template: credentialFour)
                let credentialFive = OATHSession.CredentialTemplate(type: .HOTP(), algorithm: .SHA1, secret: secret, issuer: "HOTP SHA1", name: "6 digits, counter = 0", digits: 6)
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
