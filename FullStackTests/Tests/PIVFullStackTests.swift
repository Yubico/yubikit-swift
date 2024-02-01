//
//  PIVFullStackTests.swift
//  FullStackTestsTests
//
//  Created by Jens Utbult on 2024-01-12.
//

import XCTest
import YubiKit

@testable import FullStackTests

final class PIVFullStackTests: XCTestCase {
    
    func testSignECCP256() throws {
        runAuthenticatedPIVTest { session in
            let publicKey = try await session.generateKeyInSlot(slot: .signature, type: .ECCP256)
            try await session.verifyPin("123456")
            let message = "Hello world!".data(using: .utf8)!
            let signature = try await session.signWithKeyInSlot(.signature, keyType: .ECCP256, algorithm: .ecdsaSignatureMessageX962SHA256, message: message)
            var error: Unmanaged<CFError>?
            let result = SecKeyVerifySignature(publicKey, SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256, message as CFData, signature as CFData, &error);
            if let error {
                XCTFail((error.takeRetainedValue() as Error).localizedDescription)
            }
            XCTAssert(true)
        }
    }
    
    func testSignRSA1024() throws {
        runAuthenticatedPIVTest { session in
            let publicKey = try await session.generateKeyInSlot(slot: .signature, type: .RSA1024)
            try await session.verifyPin("123456")
            let message = "Hello world!".data(using: .utf8)!
            let signature = try await session.signWithKeyInSlot(.signature, keyType: .RSA1024, algorithm: .rsaSignatureMessagePKCS1v15SHA512, message: message)
            var error: Unmanaged<CFError>?
            let result = SecKeyVerifySignature(publicKey, SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA512, message as CFData, signature as CFData, &error);
            if let error {
                XCTFail((error.takeRetainedValue() as Error).localizedDescription)
            }
            XCTAssert(true)
        }
    }
        
    func testDecryptRSA2048() throws {
        runAuthenticatedPIVTest { session in
            let publicKey = try await session.generateKeyInSlot(slot: .signature, type: .RSA2048)
            let data = "Hello world!".data(using: .utf8)!
            guard let encryptedData = SecKeyCreateEncryptedData(publicKey, .rsaEncryptionPKCS1, data as CFData, nil) else { throw "Failed to encrypt data." }
            try await session.verifyPin("123456")
            let decryptedData = try await session.decryptWithKeyInSlot(slot: .signature, algorithm: .rsaEncryptionPKCS1, encrypted: encryptedData as Data)
            XCTAssertEqual(data, decryptedData)
        }
    }
    
    func testDecryptRSA1024() throws {
        runAuthenticatedPIVTest { session in
            let publicKey = try await session.generateKeyInSlot(slot: .signature, type: .RSA1024)
            let data = "Hello world!".data(using: .utf8)!
            guard let encryptedData = SecKeyCreateEncryptedData(publicKey, .rsaEncryptionPKCS1, data as CFData, nil) else { throw "Failed to encrypt data." }
            try await session.verifyPin("123456")
            let decryptedData = try await session.decryptWithKeyInSlot(slot: .signature, algorithm: .rsaEncryptionPKCS1, encrypted: encryptedData as Data)
            XCTAssertEqual(data, decryptedData)
        }
    }
}

extension XCTestCase {
    func runPIVTest(named testName: String = #function,
                     in file: StaticString = #file,
                     at line: UInt = #line,
                     withTimeout timeout: TimeInterval = 20,
                     test: @escaping (PIVSession) async throws -> Void) {
        runAsyncTest(named: testName, in: file, at: line, withTimeout: timeout) {
            let connection = try await AllowedConnections.anyConnection()
            let session = try await PIVSession.session(withConnection: connection)
            try await test(session)
        }
    }
    
    func runAuthenticatedPIVTest(named testName: String = #function,
                     in file: StaticString = #file,
                     at line: UInt = #line,
                     withTimeout timeout: TimeInterval = 20,
                     test: @escaping (PIVSession) async throws -> Void) {
        runAsyncTest(named: testName, in: file, at: line, withTimeout: timeout) {
            let connection = try await AllowedConnections.anyConnection()
            let session = try await PIVSession.session(withConnection: connection)
            try await session.reset()
            let defaultManagementKey = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
            try await session.authenticateWith(managementKey: defaultManagementKey, keyType: .tripleDES)
            try await test(session)
        }
    }
}
