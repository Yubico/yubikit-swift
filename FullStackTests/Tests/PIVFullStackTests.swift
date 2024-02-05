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
    
    func testSharedSecretEC256() throws {
        runAuthenticatedPIVTest { session in
            let yubiKeyPublicKey = try await session.generateKeyInSlot(slot: .signature, type: .ECCP256)
            let attributes = [kSecAttrKeyType: kSecAttrKeyTypeEC,
                        kSecAttrKeySizeInBits: 256] as [CFString : Any]
            var error: Unmanaged<CFError>?
            guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error),
                  let publicKey = SecKeyCopyPublicKey(privateKey) else {
                XCTFail((error!.takeRetainedValue() as Error).localizedDescription)
                return
            }
            try await session.verifyPin("123456")
            let yubiKeySecret = try await session.calculateSecretKeyInSlot(slot: .signature, peerPublicKey: publicKey)
            let softwareSecret = SecKeyCopyKeyExchangeResult(privateKey, .ecdhKeyExchangeStandard, yubiKeyPublicKey, [String: Any]() as CFDictionary, nil)! as Data
            XCTAssert(softwareSecret == yubiKeySecret)
        }
    }
    
    func testSharedSecretEC384() throws {
        runAuthenticatedPIVTest { session in
            let yubiKeyPublicKey = try await session.generateKeyInSlot(slot: .signature, type: .ECCP384)
            let attributes = [kSecAttrKeyType: kSecAttrKeyTypeEC,
                        kSecAttrKeySizeInBits: 384] as [CFString : Any]
            var error: Unmanaged<CFError>?
            guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error),
                  let publicKey = SecKeyCopyPublicKey(privateKey) else {
                XCTFail((error!.takeRetainedValue() as Error).localizedDescription)
                return
            }
            try await session.verifyPin("123456")
            let yubiKeySecret = try await session.calculateSecretKeyInSlot(slot: .signature, peerPublicKey: publicKey)
            let softwareSecret = SecKeyCopyKeyExchangeResult(privateKey, .ecdhKeyExchangeStandard, yubiKeyPublicKey, [String: Any]() as CFDictionary, nil)! as Data
            XCTAssert(softwareSecret == yubiKeySecret)
        }
    }
    
    func testPutRSA1024Key() throws {
        runAuthenticatedPIVTest { session in
            let attributes = [kSecAttrKeyType: kSecAttrKeyTypeRSA,
                        kSecAttrKeySizeInBits: 1024] as [CFString : Any]
            var error: Unmanaged<CFError>?
            guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error),
                  let publicKey = SecKeyCopyPublicKey(privateKey) else {
                XCTFail((error!.takeRetainedValue() as Error).localizedDescription)
                return
            }
            let keyType = try await session.putKey(key: privateKey, inSlot: .signature, pinPolicy: .always, touchPolicy: .never)
            XCTAssert(keyType == .RSA1024)
            let dataToEncrypt = "Hello World!".data(using: .utf8)!
            guard let encryptedData = SecKeyCreateEncryptedData(publicKey, SecKeyAlgorithm.rsaEncryptionPKCS1, dataToEncrypt as CFData, nil) as Data? else {
                XCTFail("Failed encrypting data with SecKeyCreateEncryptedData().")
                return
            }
            try await session.verifyPin("123456")
            let decryptedData = try await session.decryptWithKeyInSlot(slot: .signature, algorithm: .rsaEncryptionPKCS1, encrypted: encryptedData)
            XCTAssert(dataToEncrypt == decryptedData)
        }
    }
    
    func testPutRSA2048Key() throws {
        runAuthenticatedPIVTest { session in
            let attributes = [kSecAttrKeyType: kSecAttrKeyTypeRSA,
                        kSecAttrKeySizeInBits: 2048] as [CFString : Any]
            var error: Unmanaged<CFError>?
            guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error),
                  let publicKey = SecKeyCopyPublicKey(privateKey) else {
                XCTFail((error!.takeRetainedValue() as Error).localizedDescription)
                return
            }
            let keyType = try await session.putKey(key: privateKey, inSlot: .signature, pinPolicy: .always, touchPolicy: .never)
            XCTAssert(keyType == .RSA2048)
            let dataToEncrypt = "Hello World!".data(using: .utf8)!
            guard let encryptedData = SecKeyCreateEncryptedData(publicKey, SecKeyAlgorithm.rsaEncryptionPKCS1, dataToEncrypt as CFData, nil) as Data? else {
                XCTFail("Failed encrypting data with SecKeyCreateEncryptedData().")
                return
            }
            try await session.verifyPin("123456")
            let decryptedData = try await session.decryptWithKeyInSlot(slot: .signature, algorithm: .rsaEncryptionPKCS1, encrypted: encryptedData)
            XCTAssert(dataToEncrypt == decryptedData)
        }
    }
    
    func testPutECCP256Key() throws {
        runAuthenticatedPIVTest { session in
            let attributes = [kSecAttrKeyType: kSecAttrKeyTypeEC,
                        kSecAttrKeySizeInBits: 256] as [CFString : Any]
            var error: Unmanaged<CFError>?
            guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error),
                  let publicKey = SecKeyCopyPublicKey(privateKey) else {
                XCTFail((error!.takeRetainedValue() as Error).localizedDescription)
                return
            }
            let keyType = try await session.putKey(key: privateKey, inSlot: .signature, pinPolicy: .always, touchPolicy: .never)
            XCTAssert(keyType == .ECCP256)
            try await session.verifyPin("123456")
            let message = "Hello World!".data(using: .utf8)!
            let signature = try await session.signWithKeyInSlot(.signature, keyType: .ECCP256, algorithm: .ecdsaSignatureMessageX962SHA256, message: message)
            let result = SecKeyVerifySignature(publicKey, SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256, message as CFData, signature as CFData, &error);
            if let error = error {
                XCTFail((error.takeRetainedValue() as Error).localizedDescription)
                return
            }
            XCTAssertTrue(result)
        }
    }
    
    func testPutECCP384Key() throws {
        runAuthenticatedPIVTest { session in
            let attributes = [kSecAttrKeyType: kSecAttrKeyTypeEC,
                        kSecAttrKeySizeInBits: 384] as [CFString : Any]
            var error: Unmanaged<CFError>?
            guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error),
                  let publicKey = SecKeyCopyPublicKey(privateKey) else {
                XCTFail((error!.takeRetainedValue() as Error).localizedDescription)
                return
            }
            let keyType = try await session.putKey(key: privateKey, inSlot: .signature, pinPolicy: .always, touchPolicy: .never)
            XCTAssert(keyType == .ECCP384)
            try await session.verifyPin("123456")
            let message = "Hello World!".data(using: .utf8)!
            let signature = try await session.signWithKeyInSlot(.signature, keyType: .ECCP384, algorithm: .ecdsaSignatureMessageX962SHA256, message: message)
            let result = SecKeyVerifySignature(publicKey, SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256, message as CFData, signature as CFData, &error);
            if let error = error {
                XCTFail((error.takeRetainedValue() as Error).localizedDescription)
                return
            }
            XCTAssertTrue(result)
        }
    }
    
    func testGenerateRSA1024Key() throws {
        runAuthenticatedPIVTest { session in
            let publicKey = try await session.generateKeyInSlot(slot: .signature, type: .RSA1024, pinPolicy: .always, touchPolicy: .cached)
            let attributes = SecKeyCopyAttributes(publicKey) as! [String: Any]
            XCTAssert(attributes[kSecAttrKeySizeInBits as String] as! Int == 1024)
            XCTAssert(attributes[kSecAttrKeyType as String] as! String == kSecAttrKeyTypeRSA as String)
            XCTAssert(attributes[kSecAttrKeyClass as String] as! String == kSecAttrKeyClassPublic as String)
        }
    }
    
    func testGenerateRSA2048Key() throws {
        runAuthenticatedPIVTest { session in
            let publicKey = try await session.generateKeyInSlot(slot: .signature, type: .RSA2048, pinPolicy: .always, touchPolicy: .cached)
            let attributes = SecKeyCopyAttributes(publicKey) as! [String: Any]
            XCTAssert(attributes[kSecAttrKeySizeInBits as String] as! Int == 2048)
            XCTAssert(attributes[kSecAttrKeyType as String] as! String == kSecAttrKeyTypeRSA as String)
            XCTAssert(attributes[kSecAttrKeyClass as String] as! String == kSecAttrKeyClassPublic as String)
        }
    }
    
    func testGenerateECCP256Key() throws {
        runAuthenticatedPIVTest { session in
            let publicKey = try await session.generateKeyInSlot(slot: .signature, type: .ECCP256, pinPolicy: .always, touchPolicy: .cached)
            let attributes = SecKeyCopyAttributes(publicKey) as! [String: Any]
            XCTAssert(attributes[kSecAttrKeySizeInBits as String] as! Int == 256)
            XCTAssert(attributes[kSecAttrKeyType as String] as! String == kSecAttrKeyTypeEC as String)
            XCTAssert(attributes[kSecAttrKeyClass as String] as! String == kSecAttrKeyClassPublic as String)
        }
    }

    
    func testGenerateECCP384Key() throws {
        runAuthenticatedPIVTest { session in
            let publicKey = try await session.generateKeyInSlot(slot: .signature, type: .ECCP384, pinPolicy: .always, touchPolicy: .cached)
            let attributes = SecKeyCopyAttributes(publicKey) as! [String: Any]
            XCTAssert(attributes[kSecAttrKeySizeInBits as String] as! Int == 384)
            XCTAssert(attributes[kSecAttrKeyType as String] as! String == kSecAttrKeyTypeEC as String)
            XCTAssert(attributes[kSecAttrKeyClass as String] as! String == kSecAttrKeyClassPublic as String)
        }
    }

    func testAttestRSAKey() throws {
        runAuthenticatedPIVTest { session in
            let publicKey = try await session.generateKeyInSlot(slot: .keyManagement, type: .RSA1024)
            let cert = try await session.attestKeyInSlot(slot: .keyManagement)
            let attestKey = SecCertificateCopyKey(cert)!
            let attestKeyData = SecKeyCopyExternalRepresentation(attestKey, nil)!
            let keyData = SecKeyCopyExternalRepresentation(publicKey, nil)!
            XCTAssert((attestKeyData as Data) == (keyData as Data))
            
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
