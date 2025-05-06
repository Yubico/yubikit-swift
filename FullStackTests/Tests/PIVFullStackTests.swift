//
//  PIVFullStackTests.swift
//  FullStackTestsTests
//
//  Created by Jens Utbult on 2024-01-12.
//

import XCTest
import OSLog

@testable import YubiKit
@testable import FullStackTests

final class PIVFullStackTests: XCTestCase {
    
    let defaultManagementKey = Data(hexEncodedString: "010203040506070801020304050607080102030405060708")!
    
    func testSignECCP256() throws {
        runAuthenticatedPIVTest { session in
            let publicKey = try await session.generateKeyInSlot(slot: .signature, type: .ECCP256)
            try await session.verifyPin("123456")
            let message = "Hello world!".data(using: .utf8)!
            let signature = try await session.signWithKeyInSlot(.signature, keyType: .ECCP256, algorithm: .ecdsaSignatureMessageX962SHA256, message: message)
            var error: Unmanaged<CFError>?
            let result = SecKeyVerifySignature(publicKey, SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256, message as CFData, signature as CFData, &error);
            XCTAssertTrue(result)
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
            XCTAssertTrue(result)
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
            let encryptedData = try XCTUnwrap(SecKeyCreateEncryptedData(publicKey, .rsaEncryptionPKCS1, data as CFData, nil),
                                              "Failed to encrypt data.")
            try await session.verifyPin("123456")
            let decryptedData = try await session.decryptWithKeyInSlot(slot: .signature, algorithm: .rsaEncryptionPKCS1, encrypted: encryptedData as Data)
            XCTAssertEqual(data, decryptedData)
        }
    }
    
    func testDecryptRSA1024() throws {
        runAuthenticatedPIVTest { session in
            let publicKey = try await session.generateKeyInSlot(slot: .signature, type: .RSA1024)
            let data = "Hello world!".data(using: .utf8)!

            let encryptedData = try XCTUnwrap(
                SecKeyCreateEncryptedData(publicKey,
                                          .rsaEncryptionPKCS1,
                                          data as CFData,
                                          nil),
                "Failed to encrypt data.")

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
            let publicKey = try await session.generateKeyInSlot(slot: .signature, type: .RSA1024, pinPolicy: .never, touchPolicy: .cached)
            let attributes = SecKeyCopyAttributes(publicKey) as! [String: Any]
            XCTAssert(attributes[kSecAttrKeySizeInBits as String] as! Int == 1024)
            XCTAssert(attributes[kSecAttrKeyType as String] as! String == kSecAttrKeyTypeRSA as String)
            XCTAssert(attributes[kSecAttrKeyClass as String] as! String == kSecAttrKeyClassPublic as String)
        }
    }
    
    func testGenerateRSA2048Key() throws {
        runAuthenticatedPIVTest(withTimeout: 50) { session in
            let publicKey = try await session.generateKeyInSlot(slot: .signature, type: .RSA2048, pinPolicy: .always, touchPolicy: .cached)
            let attributes = SecKeyCopyAttributes(publicKey) as! [String: Any]
            XCTAssert(attributes[kSecAttrKeySizeInBits as String] as! Int == 2048)
            XCTAssert(attributes[kSecAttrKeyType as String] as! String == kSecAttrKeyTypeRSA as String)
            XCTAssert(attributes[kSecAttrKeyClass as String] as! String == kSecAttrKeyClassPublic as String)
        }
    }
    
    func testGenerateRSA3072Key() throws {
        runAuthenticatedPIVTest(withTimeout: 200) { session in
            let publicKey = try await session.generateKeyInSlot(slot: .signature, type: .RSA3072, pinPolicy: .always, touchPolicy: .cached)
            let attributes = SecKeyCopyAttributes(publicKey) as! [String: Any]
            XCTAssert(attributes[kSecAttrKeySizeInBits as String] as! Int == 3072)
            XCTAssert(attributes[kSecAttrKeyType as String] as! String == kSecAttrKeyTypeRSA as String)
            XCTAssert(attributes[kSecAttrKeyClass as String] as! String == kSecAttrKeyClassPublic as String)
        }
    }
    
    func testGenerateRSA4096Key() throws {
        runAuthenticatedPIVTest(withTimeout: 200) { session in
            let publicKey = try await session.generateKeyInSlot(slot: .signature, type: .RSA4096, pinPolicy: .always, touchPolicy: .cached)
            let attributes = SecKeyCopyAttributes(publicKey) as! [String: Any]
            XCTAssert(attributes[kSecAttrKeySizeInBits as String] as! Int == 4096)
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
            let publicKey = try await session.generateKeyInSlot(slot: .signature, type: .RSA1024)
            XCTAssertNotNil(publicKey)
            let cert = try await session.attestKeyInSlot(slot: .signature)
            XCTAssertNotNil(cert)
            let attestKey = SecCertificateCopyKey(cert)!
            let attestKeyData = SecKeyCopyExternalRepresentation(attestKey, nil)!
            let keyData = SecKeyCopyExternalRepresentation(publicKey, nil)!
            XCTAssert((attestKeyData as Data) == (keyData as Data))
        }
    }
    
    let testCertificate = SecCertificateCreateWithData(nil, Data(base64Encoded: "MIIBKzCB0qADAgECAhQTuU25u6oazORvKfTleabdQaDUGzAKBggqhkjOPQQDAjAWMRQwEgYDVQQDDAthbW9zLmJ1cnRvbjAeFw0yMTAzMTUxMzU5MjVaFw0yODA1MTcwMDAwMDBaMBYxFDASBgNVBAMMC2Ftb3MuYnVydG9uMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEofwN6S+atSZmzeLK7aSI+mJJwxh0oUBiCOngHLeToYeanrTGvCZQ2AK/R9esnqSxMyBUDp91UO4F6U4c6RTooTAKBggqhkjOPQQDAgNIADBFAiAnj/KUSpW7l5wnenQEbwWudK/7q3WtyrqdB0H1xc258wIhALDLImzu3S+0TT2/ggM95LLWE4Llfa2RQM71bnW6zqqn")! as CFData)!
    
    func testPutAndReadCertificate() throws {
        runAuthenticatedPIVTest { session in
            try await session.putCertificate(certificate: self.testCertificate, inSlot: .authentication, compress: false)
            let retrievedCertificate = try await session.getCertificateInSlot(.authentication)
            XCTAssert(self.testCertificate == retrievedCertificate)
        }
    }
    
    func testMoveKey() throws {
        runAuthenticatedPIVTest { session in
            guard session.supports(PIVSessionFeature.moveDelete) else { print("⚠️ Skip testMoveKey()"); return }
            try await session.putCertificate(certificate: self.testCertificate, inSlot: .authentication)
            try await session.putCertificate(certificate: self.testCertificate, inSlot: .signature)
            let publicKey = try await session.generateKeyInSlot(slot: .authentication, type: .RSA1024, pinPolicy: .always, touchPolicy: .always)
            let authSlotMetadata = try await session.getSlotMetadata(.authentication)
            XCTAssertEqual(publicKey, authSlotMetadata.publicKey)
            try await session.moveKey(sourceSlot: .authentication, destinationSlot: .signature)
            let signSlotMetadata = try await session.getSlotMetadata(.signature)
            XCTAssertEqual(publicKey, signSlotMetadata.publicKey)
            do {
                _ = try await session.getSlotMetadata(.authentication)
                XCTFail("Got metadata when we should have thrown a referenceDataNotFound exception.")
            } catch {
                guard let responseError = error as? ResponseError else { XCTFail("Unexpected error: \(error)"); return }
                XCTAssertTrue(responseError.responseStatus.status == .referencedDataNotFound)
            }
        }
    }
    
    func testDeleteKey() throws {
        runAuthenticatedPIVTest { session in
            guard session.supports(PIVSessionFeature.moveDelete) else { print("⚠️ Skip testDeleteKey()"); return }
            try await session.putCertificate(certificate: self.testCertificate, inSlot: .authentication, compress: true)
            let publicKey = try await session.generateKeyInSlot(slot: .authentication, type: .RSA1024, pinPolicy: .always, touchPolicy: .always)
            let slotMetadata = try await session.getSlotMetadata(.authentication)
            XCTAssertEqual(publicKey, slotMetadata.publicKey)
            try await session.deleteKey(in: .authentication)
            do {
                _ = try await session.getSlotMetadata(.authentication)
                XCTFail("Got metadata when we should have thrown a referenceDataNotFound exception.")
            } catch {
                guard let responseError = error as? ResponseError else { XCTFail("Unexpected error: \(error)"); return }
                XCTAssertTrue(responseError.responseStatus.status == .referencedDataNotFound)
            }
        }
    }
    
    func testPutCompressedAndReadCertificate() throws {
        runAuthenticatedPIVTest { session in
            try await session.putCertificate(certificate: self.testCertificate, inSlot: .authentication, compress: true)
            let retrievedCertificate = try await session.getCertificateInSlot(.authentication)
            XCTAssert(self.testCertificate == retrievedCertificate)
        }
    }
    
    func testPutAndDeleteCertificate() throws {
        runAuthenticatedPIVTest { session in
            try await session.putCertificate(certificate: self.testCertificate, inSlot: .authentication)
            try await session.deleteCertificateInSlot(slot: .authentication)
            do {
                _ = try await session.getCertificateInSlot(.authentication)
                XCTFail("Deleted certificate still present on YubiKey.")
            } catch {
                guard let error = error as? ResponseError else {  XCTFail("Deleted certificate returned unexpected error: \(error)"); return }
                XCTAssert(error.responseStatus.status == .fileNotFound)
            }
        }
    }
    
    func testAuthenticateWithDefaultManagementKey() throws {
        runPIVTest { session in
            do {
                let keyType: PIVManagementKeyType
                if session.supports(PIVSessionFeature.metadata) {
                    let metadata = try await session.getManagementKeyMetadata()
                    keyType = metadata.keyType
                } else {
                    keyType = .tripleDES
                }
                try await session.authenticateWith(managementKey: self.defaultManagementKey, keyType: keyType)
            } catch {
                XCTFail("Failed authenticating with default management key.")
            }
        }
    }
    
    func testSet3DESManagementKey() throws {
        runAuthenticatedPIVTest { session in
            guard session.supports(PIVSessionFeature.aesKey) else { print("⚠️ Skip testSet3DESManagementKey()"); return }
            let newManagementKey = Data(hexEncodedString: "3ec950f1c126b314a80edd752694c328656db96f1c65cc4f")!
            do {
                try await session.setManagementKey(newManagementKey, type: .tripleDES, requiresTouch: false)
                try await session.authenticateWith(managementKey: newManagementKey, keyType: .tripleDES)
            } catch {
                XCTFail("Failed setting new management key with: \(error)")
            }
        }
    }
    
    func testSetAESManagementKey() throws {
        runAuthenticatedPIVTest { session in
            guard session.supports(PIVSessionFeature.aesKey) else { print("⚠️ Skip testSetAESManagementKey()"); return }
            let newManagementKey = Data(hexEncodedString: "f7ef787b46aa50de066bdade00aee17fc2b710372b722de5")!
            do {
                try await session.setManagementKey(newManagementKey, type: .AES192, requiresTouch: false)
                try await session.authenticateWith(managementKey: newManagementKey, keyType: .AES192)
            } catch {
                XCTFail("Failed setting new management key with: \(error)")
            }
        }
    }
    
    func testAuthenticateWithWrongManagementKey() throws {
        runPIVTest { session in
            let wrongManagementKey = Data(hexEncodedString: "010101010101010101010101010101010101010101010101")!
            do {
                let keyType: PIVManagementKeyType
                if session.supports(PIVSessionFeature.metadata) {
                    let metadata = try await session.getManagementKeyMetadata()
                    keyType = metadata.keyType
                } else {
                    keyType = .tripleDES
                }
                try await session.authenticateWith(managementKey: wrongManagementKey, keyType: keyType)
                XCTFail("Successfully authenticated with the wrong management key.")
            } catch {
                guard let error = error as? ResponseError else { XCTFail("Failed with unexpected error: \(error)"); return }
                XCTAssert(error.responseStatus.status == .securityConditionNotSatisfied)
            }
        }
    }
    
    func testVerifyPIN() throws {
        runAuthenticatedPIVTest { session in
            do {
                let result = try await session.verifyPin("123456")
                if case .success(let counter) = result {
                    XCTAssertEqual(counter, 3)
                } else {
                    XCTFail("Got unexpected result from verifyPin: \(result)")
                }
            } catch {
                XCTFail("Got unexpected error verifying pin: \(error)")
            }
        }
    }
    
    func testVerifyPINRetryCount() throws {
        runAuthenticatedPIVTest { session in
            let resultOne = try await session.verifyPin("654321")
            if case .fail(let counter) = resultOne {
                XCTAssertEqual(counter, 2)
            } else {
                XCTFail("Got unexpected result from verifyPin: \(resultOne)")
            }
            let resultTwo = try await session.verifyPin("101010")
            if case .fail(let counter) = resultTwo {
                XCTAssertEqual(counter, 1)
            } else {
                XCTFail("Got unexpected result from verifyPin: \(resultTwo)")
            }
            let resultThree = try await session.verifyPin("142857")
            XCTAssert(resultThree == .pinLocked)
            let resultFour = try await session.verifyPin("740737")
            XCTAssert(resultFour == .pinLocked)
        }
    }
    
    func testGetPinAttempts() throws {
        runAuthenticatedPIVTest { session in
            var count = try await session.getPinAttempts()
            XCTAssertEqual(count, 3)
            _ = try await session.verifyPin("740601")
            count = try await session.getPinAttempts()
            XCTAssertEqual(count, 2)
        }
    }
    
    func testSetPinPukAttempts() throws {
        runAuthenticatedPIVTest { session in
            try await session.verifyPin("123456")
            try await session.set(pinAttempts: 5, pukAttempts: 6)
            if session.supports(PIVSessionFeature.metadata) {
                let pinResult = try await session.getPinMetadata()
                XCTAssertEqual(pinResult.retriesRemaining, 5)
                let pukResult = try await session.getPukMetadata()
                XCTAssertEqual(pukResult.retriesRemaining, 6)
            } else {
                let result = try await session.getPinAttempts()
                XCTAssertEqual(result, 5)
            }
        }
    }
    
    func testVersion() throws {
        runPIVTest { session in
            let version = session.version
            XCTAssertEqual(version.major, 5)
            XCTAssert(version.minor == 2 || version.minor == 3 || version.minor == 4 || version.minor == 7)
            print("➡️ Version: \(session.version.major).\(session.version.minor).\(session.version.micro)")
        }
    }
    
    func testSerialNumber() throws {
        runPIVTest { session in
            guard session.supports(PIVSessionFeature.serialNumber) else { print("⚠️ Skip testSerialNumber()"); return }
            let serialNumber = try await session.getSerialNumber()
            XCTAssert(serialNumber > 0)
            print("➡️ Serial number: \(serialNumber)")
        }
    }
    
    func testManagementKeyMetadata() throws {
        runPIVTest { session in
            guard session.supports(PIVSessionFeature.metadata) else { print("⚠️ Skip testManagementKeyMetadata()"); return }
            let metadata = try await session.getManagementKeyMetadata()
            XCTAssertEqual(metadata.isDefault, true)
            print("➡️ Management key type: \(metadata.keyType)")
            print("➡️ Management touch policy: \(metadata.touchPolicy)")
        }
        
    }
    
    func testSlotMetadata() throws {
        runAuthenticatedPIVTest { session in
            guard session.supports(PIVSessionFeature.metadata) else { print("⚠️ Skip testSlotMetadata()"); return }
            var publicKey = try await session.generateKeyInSlot(slot: .authentication, type: .ECCP256, pinPolicy: .always, touchPolicy: .always)
            var metadata = try await session.getSlotMetadata(.authentication)
            XCTAssertEqual(metadata.keyType, .ECCP256)
            XCTAssertEqual(metadata.pinPolicy, .always)
            XCTAssertEqual(metadata.touchPolicy, .always)
            XCTAssertEqual(metadata.generated, true)
            XCTAssertEqual(metadata.publicKey, publicKey)

            publicKey = try await session.generateKeyInSlot(slot: .authentication, type: .ECCP384, pinPolicy: .never, touchPolicy: .never)
            metadata = try await session.getSlotMetadata(.authentication)
            XCTAssertEqual(metadata.keyType, .ECCP384)
            XCTAssertEqual(metadata.pinPolicy, .never)
            XCTAssertEqual(metadata.touchPolicy, .never)
            XCTAssertEqual(metadata.generated, true)
            XCTAssertEqual(metadata.publicKey, publicKey)

            publicKey = try await session.generateKeyInSlot(slot: .authentication, type: .ECCP256, pinPolicy: .once, touchPolicy: .cached)
            metadata = try await session.getSlotMetadata(.authentication)
            XCTAssertEqual(metadata.keyType, .ECCP256)
            XCTAssertEqual(metadata.pinPolicy, .once)
            XCTAssertEqual(metadata.touchPolicy, .cached)
            XCTAssertEqual(metadata.generated, true)
            XCTAssertEqual(metadata.publicKey, publicKey)
        }
        
    }
    
    func testAESManagementKeyMetadata() throws {
        runAuthenticatedPIVTest { session in
            guard session.supports(PIVSessionFeature.metadata) else { print("⚠️ Skip testAESManagementKeyMetadata()"); return }
            let aesManagementKey = Data(hexEncodedString: "f7ef787b46aa50de066bdade00aee17fc2b710372b722de5")!
            try await session.setManagementKey(aesManagementKey, type: .AES192, requiresTouch: true)
            let metadata = try await session.getManagementKeyMetadata()
            XCTAssertEqual(metadata.isDefault, false)
            XCTAssertEqual(metadata.keyType, .AES192)
            XCTAssertEqual(metadata.touchPolicy, .always)
        }
    }
    
    func testPinMetadata() throws {
        runAuthenticatedPIVTest { session in
            guard session.supports(PIVSessionFeature.metadata) else { print("⚠️ Skip testPinMetadata()"); return }
            let result = try await session.getPinMetadata()
            XCTAssertEqual(result.isDefault, true)
            XCTAssertEqual(result.retriesTotal, 3)
            XCTAssertEqual(result.retriesRemaining, 3)
        }
    }
    
    func testPinMetadataRetries() throws {
        runAuthenticatedPIVTest { session in
            guard session.supports(PIVSessionFeature.metadata) else { print("⚠️ Skip testPinMetadataRetries()"); return }
            try await session.verifyPin("111111")
            let result = try await session.getPinMetadata()
            XCTAssertEqual(result.isDefault, true)
            XCTAssertEqual(result.retriesTotal, 3)
            XCTAssertEqual(result.retriesRemaining, 2)
        }
    }
    
    func testPukMetadata() throws {
        runPIVTest { session in
            guard session.supports(PIVSessionFeature.metadata) else { print("⚠️ Skip testPukMetadata()"); return }
            let result = try await session.getPukMetadata()
            XCTAssertEqual(result.isDefault, true)
            XCTAssertEqual(result.retriesTotal, 3)
            XCTAssertEqual(result.retriesRemaining, 3)
        }
        
    }
    
    func testSetPin() throws {
        runPIVTest { session in
            try await session.setPin("654321", oldPin: "123456")
            let result = try await session.verifyPin("654321")
            switch result {
            case .success(let retries):
                XCTAssertEqual(retries, 3)
            case .fail(_):
                XCTFail()
            case .pinLocked:
                XCTFail()
            }
        }
    }
    
    func testUnblockPin() throws {
        runPIVTest { session in
            try await session.blockPin()
            let verifyBlockedPin = try await session.verifyPin("123456")
            guard verifyBlockedPin == .pinLocked else { XCTFail("Pin failed to block."); return }
            try await session.unblockPinWithPuk("12345678", newPin: "222222")
            let verifyUnblockedPin = try await session.verifyPin("222222")
            switch verifyUnblockedPin {
            case .success(_):
                return;
            case .fail(_):
                XCTFail("Failed verifiying with unblocked pin.")
            case .pinLocked:
                XCTFail("Pin still blocked after unblocking with puk.")
            }
        }
    }
    
    func testSetPukAndUnblock() throws {
        runPIVTest { session in
            try await session.setPuk("87654321", oldPuk: "12345678")
            try await session.blockPin()
            try await session.unblockPinWithPuk("87654321", newPin: "654321")
            let result = try await session.verifyPin("654321")
            switch result {
            case .success(_):
                return
            case .fail(_):
                XCTFail("Failed verifying new pin.")
            case .pinLocked:
                XCTFail("Pin still blocked after unblocking with new puk.")
            }
        }
        
    }

    // This will test auth on a YubiKey Bio. To run the test at least one fingerprint needs to be registered.
    func testBioAuthentication() throws {
        runAsyncTest {
            let connection = try await AllowedConnections.anyConnection()
            let managementSession = try await ManagementSession.session(withConnection: connection)
            let deviceInfo = try await managementSession.getDeviceInfo()
            guard deviceInfo.formFactor == .usbCBio || deviceInfo.formFactor == .usbABio else {
                print("⚠️ Skip testBioAuthentication()")
                return
            }
            let pivSession = try await PIVSession.session(withConnection: connection)
            var bioMetadata = try await pivSession.getBioMetadata()
            if !bioMetadata.isConfigured {
                let message = "No fingerprints registered for this yubikey or there's an error in getBioMetadata()."
                print("⚠️ \(message)")
                XCTFail(message)
                return
            }
            XCTAssertTrue(bioMetadata.attemptsRemaining > 0)
            var verifyResult = try await pivSession.verifyUv(requestTemporaryPin: false, checkOnly: false)
            XCTAssertNil(verifyResult)
            Logger.test.debug("✅ verifyUV() passed")
            guard let pinData = try await pivSession.verifyUv(requestTemporaryPin: true, checkOnly: false) else {
                XCTFail("Pin data returned was nil. Expected a value.")
                return
            }
            Logger.test.debug("✅ got temporary pin: \(pinData.hexEncodedString).")
            bioMetadata = try await pivSession.getBioMetadata()
            XCTAssertTrue(bioMetadata.temporaryPin)
            Logger.test.debug("✅ temporary pin reported as set.")
            verifyResult = try await pivSession.verifyUv(requestTemporaryPin: false, checkOnly: true)
            XCTAssertNil(verifyResult)
            Logger.test.debug("✅ verifyUv successful.")
            try await pivSession.verifyTemporaryPin(pinData)
            Logger.test.debug("✅ temporary pin verified.")
        }
    }
    
    func testBioPinPolicyErrorOnNonBioKey() throws {
        runAsyncTest {
            let connection = try await AllowedConnections.anyConnection()
            let managementSession = try await ManagementSession.session(withConnection: connection)
            let deviceInfo = try await managementSession.getDeviceInfo()
            guard deviceInfo.formFactor != .usbCBio && deviceInfo.formFactor != .usbABio else {
                print("⚠️ Skip testBioPinPolicyErrorOnNonBioKey() since this is a bio key.")
                return
            }
            let session = try await PIVSession.session(withConnection: connection)
            try await self.authenticate(with: session)
            do {
                _ = try await session.generateKeyInSlot(slot: .signature, type: .ECCP384, pinPolicy: .matchAlways, touchPolicy: .defaultPolicy)
            } catch {
                guard let sessionError = error as? SessionError else { throw error }
                XCTAssertEqual(sessionError, SessionError.notSupported)
            }
            do {
                _ = try await session.generateKeyInSlot(slot: .signature, type: .ECCP384, pinPolicy: .matchOnce, touchPolicy: .defaultPolicy)
            } catch {
                guard let sessionError = error as? SessionError else { throw error }
                XCTAssertEqual(sessionError, SessionError.notSupported)
            }
        }
    }
}

extension XCTestCase {
    
    func authenticate(with session: PIVSession) async throws {
        let defaultManagementKey = Data(hexEncodedString: "010203040506070801020304050607080102030405060708")!
        let keyType: PIVManagementKeyType
        if session.supports(PIVSessionFeature.metadata) {
            let metadata = try await session.getManagementKeyMetadata()
            keyType = metadata.keyType
        } else {
            keyType = .tripleDES
        }
        try await session.authenticateWith(managementKey: defaultManagementKey, keyType: keyType)
    }
    
    func runPIVTest(named testName: String = #function,
                     in file: StaticString = #file,
                     at line: UInt = #line,
                     withTimeout timeout: TimeInterval = 20,
                     test: @escaping (PIVSession) async throws -> Void) {
        runAsyncTest(named: testName, in: file, at: line, withTimeout: timeout) {
            let connection = try await AllowedConnections.anyConnection()
            let session = try await PIVSession.session(withConnection: connection)
            try await session.reset()
            Logger.test.debug("⬇️ ⬇️ ⬇️ ⬇️ ⬇️ ⬇️ ⬇️ ⬇️ PIV Session test ⬇️ ⬇️ ⬇️ ⬇️ ⬇️ ⬇️ ⬇️ ⬇️")
            try await test(session)
            Logger.test.debug("✅ \(testName) passed")
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
            try await self.authenticate(with: session)
            Logger.test.debug("⬇️ ⬇️ ⬇️ ⬇️ ⬇️ ⬇️ ⬇️ ⬇️ PIV Session test ⬇️ ⬇️ ⬇️ ⬇️ ⬇️ ⬇️ ⬇️ ⬇️")
            try await test(session)
            Logger.test.debug("✅ \(testName) passed")
        }
    }
}
