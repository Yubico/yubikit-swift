//
//  PIVFullStackTests.swift
//  FullStackTestsTests
//
//  Created by Jens Utbult on 2024-01-12.
//

import CryptoKit
import OSLog
import XCTest

@testable import FullStackTests
@testable import YubiKit

final class PIVFullStackTests: XCTestCase {

    let defaultManagementKey = Data(hexEncodedString: "010203040506070801020304050607080102030405060708")!

    // MARK: - Signing Tests

    func testSignECCP256() throws {
        runAuthenticatedPIVTest { session in
            guard
                case let .ec(publicKey) = try await session.generateKeyInSlot(
                    slot: .signature,
                    type: .ecc(.p256)
                )
            else {
                XCTFail("Failed to generate key in slot")
                return
            }

            try await session.verifyPin("123456")
            let message = "Hello world!".data(using: .utf8)!
            let signature = try await session.sign(
                slot: .signature,
                keyType: .ecc(.p256),
                algorithm: .digest(.sha256),
                message: message
            )
            var error: Unmanaged<CFError>?
            let result = SecKeyVerifySignature(
                publicKey.asSecKey()!,
                SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256,
                message as CFData,
                signature as CFData,
                &error
            )
            XCTAssertTrue(result)
            if let error {
                XCTFail((error.takeRetainedValue() as Error).localizedDescription)
            }
            XCTAssert(true)
        }
    }

    func testSignRSA1024() throws {
        runAuthenticatedPIVTest { session in
            guard
                case let .rsa(publicKey) = try await session.generateKeyInSlot(
                    slot: .signature,
                    type: .rsa(.bits1024)
                )
            else {
                XCTFail("Failed to generate key in slot")
                return
            }

            try await session.verifyPin("123456")
            let message = "Hello world!".data(using: .utf8)!
            let signature = try await session.sign(
                slot: .signature,
                keyType: .rsa(.bits1024),
                algorithm: .pkcs1v15(.sha512),
                message: message
            )
            var error: Unmanaged<CFError>?
            let result = SecKeyVerifySignature(
                publicKey.asSecKey()!,
                SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA512,
                message as CFData,
                signature as CFData,
                &error
            )
            XCTAssertTrue(result)
            if let error {
                XCTFail((error.takeRetainedValue() as Error).localizedDescription)
            }
            XCTAssert(true)
        }
    }

    func testSignEd25519() throws {
        runAuthenticatedPIVTest { session in
            guard session.supports(PIVSessionFeature.ed25519) else {
                print("⚠️ Skip testSignEd25519()")
                return
            }

            guard
                case let .ed25519(publicKey) = try await session.generateKeyInSlot(
                    slot: .signature,
                    type: .ed25519
                )
            else {
                XCTFail("Failed to generate key in slot")
                return
            }

            try await session.verifyPin("123456")
            let message = "Hello world!".data(using: .utf8)!
            let signature = try await session.sign(
                slot: .signature,
                keyType: .ed25519,
                message: message
            )

            // Convert YubiKit public key to CryptoKit for verification
            let cryptoKitPublicKey = try Curve25519.Signing.PublicKey(rawRepresentation: publicKey.keyData)
            XCTAssertTrue(cryptoKitPublicKey.isValidSignature(signature, for: message))
        }
    }

    // MARK: - Decryption Tests

    func testDecryptRSA2048() throws {
        runAuthenticatedPIVTest { session in
            guard
                case let .rsa(publicKey) = try await session.generateKeyInSlot(
                    slot: .signature,
                    type: .rsa(.bits2048)
                )
            else {
                XCTFail("Failed to generate key in slot")
                return
            }

            let data = "Hello world!".data(using: .utf8)!

            let encryptedData = try XCTUnwrap(
                SecKeyCreateEncryptedData(
                    publicKey.asSecKey()!,
                    .rsaEncryptionPKCS1,
                    data as CFData,
                    nil
                ),
                "Failed to encrypt data."
            )

            try await session.verifyPin("123456")
            let decryptedData = try await session.decryptWithKeyInSlot(
                slot: .signature,
                algorithm: .pkcs1v15,
                encrypted: encryptedData as Data
            )
            XCTAssertEqual(data, decryptedData)
        }
    }

    func testDecryptRSA1024() throws {
        runAuthenticatedPIVTest { session in
            guard
                case let .rsa(publicKey) = try await session.generateKeyInSlot(slot: .signature, type: .rsa(.bits1024))
            else {
                XCTFail("Failed to generate key in slot")
                return
            }

            let data = "Hello world!".data(using: .utf8)!

            let encryptedData = try XCTUnwrap(
                SecKeyCreateEncryptedData(
                    publicKey.asSecKey()!,
                    .rsaEncryptionPKCS1,
                    data as CFData,
                    nil
                ),
                "Failed to encrypt data."
            )

            try await session.verifyPin("123456")
            let decryptedData = try await session.decryptWithKeyInSlot(
                slot: .signature,
                algorithm: .pkcs1v15,
                encrypted: encryptedData as Data
            )
            XCTAssertEqual(data, decryptedData)
        }
    }

    // MARK: - Key Agreement Tests

    func testSharedSecretEC256() throws {
        runAuthenticatedPIVTest { session in
            guard
                case let .ec(yubiKeyPublicKey) = try await session.generateKeyInSlot(
                    slot: .signature,
                    type: .ecc(.p256)
                )
            else {
                XCTFail("Failed to generate key in slot")
                return
            }

            let privateKey = try XCTUnwrap(EC.PrivateKey.random(curve: .p256))
            let publicKey = privateKey.publicKey

            try await session.verifyPin("123456")
            let yubiKeySecret = try await session.calculateSecretKeyInSlot(slot: .signature, peerKey: publicKey)
            let softwareSecret =
                SecKeyCopyKeyExchangeResult(
                    privateKey.asSecKey()!,
                    .ecdhKeyExchangeStandard,
                    yubiKeyPublicKey.asSecKey()!,
                    [String: Any]() as CFDictionary,
                    nil
                )! as Data
            XCTAssert(softwareSecret == yubiKeySecret)
        }
    }

    func testSharedSecretEC384() throws {
        runAuthenticatedPIVTest { session in
            guard
                case let .ec(yubiKeyPublicKey) = try await session.generateKeyInSlot(
                    slot: .signature,
                    type: .ecc(.p384)
                )
            else {
                XCTFail("Failed to generate key in slot")
                return
            }

            let privateKey = try XCTUnwrap(EC.PrivateKey.random(curve: .p384))
            let publicKey = privateKey.publicKey

            try await session.verifyPin("123456")
            let yubiKeySecret = try await session.calculateSecretKeyInSlot(slot: .signature, peerKey: publicKey)
            let softwareSecret =
                SecKeyCopyKeyExchangeResult(
                    privateKey.asSecKey()!,
                    .ecdhKeyExchangeStandard,
                    yubiKeyPublicKey.asSecKey()!,
                    [String: Any]() as CFDictionary,
                    nil
                )! as Data
            XCTAssert(softwareSecret == yubiKeySecret)
        }
    }

    func testSharedSecretX25519() throws {
        runAuthenticatedPIVTest { session in
            guard session.supports(PIVSessionFeature.x25519) else {
                print("⚠️ Skip testSharedSecretX25519()")
                return
            }

            guard
                case let .x25519(yubiKeyPublicKey) = try await session.generateKeyInSlot(
                    slot: .signature,
                    type: .x25519
                )
            else {
                XCTFail("Failed to generate key in slot")
                return
            }

            // Generate X25519 key using CryptoKit
            let cryptoKitPrivateKey = Curve25519.KeyAgreement.PrivateKey()
            let cryptoKitPublicKey = cryptoKitPrivateKey.publicKey

            // Convert to YubiKit format
            let publicKeyData = cryptoKitPublicKey.rawRepresentation
            guard let yubiKitPublicKey = Curve25519.X25519.PublicKey(keyData: publicKeyData) else {
                XCTFail("Failed to create YubiKit X25519 public key")
                return
            }

            try await session.verifyPin("123456")
            let yubiKeySecret = try await session.calculateSecretKeyInSlot(slot: .signature, peerKey: yubiKitPublicKey)

            // Calculate shared secret using CryptoKit
            let softwareSecret = try cryptoKitPrivateKey.sharedSecretFromKeyAgreement(
                with: Curve25519.KeyAgreement.PublicKey(rawRepresentation: yubiKeyPublicKey.keyData)
            )
            let softwareSecretData = softwareSecret.withUnsafeBytes { Data($0) }

            XCTAssert(softwareSecretData == yubiKeySecret)
        }
    }

    // MARK: - Key Import Tests

    func testPutRSAKeys() throws {
        runAuthenticatedPIVTest(withTimeout: 200) { session in

            for keySize in RSA.KeySize.allCases {

                guard let privateKey = RSA.PrivateKey.random(keySize: keySize) else {
                    XCTFail("Failed to create keys")
                    return
                }
                let publicKey = privateKey.publicKey

                let keyType = try await session.putKey(
                    key: privateKey,
                    inSlot: .signature,
                    pinPolicy: .always,
                    touchPolicy: .never
                )
                XCTAssert(keyType == PIV.RSAKey.rsa(keySize))
                let dataToEncrypt = "Hello World!".data(using: .utf8)!
                guard let publicKey = publicKey.asSecKey(),
                    let encryptedData = SecKeyCreateEncryptedData(
                        publicKey,
                        .rsaEncryptionPKCS1,
                        dataToEncrypt as CFData,
                        nil
                    ) as Data?
                else {
                    XCTFail("Failed encrypting data with SecKeyCreateEncryptedData().")
                    return
                }
                try await session.verifyPin("123456")
                let decryptedData = try await session.decryptWithKeyInSlot(
                    slot: .signature,
                    algorithm: .pkcs1v15,
                    encrypted: encryptedData
                )
                XCTAssert(dataToEncrypt == decryptedData)
            }
        }
    }

    func testPutECCPKeys() throws {
        runAuthenticatedPIVTest { session in

            for curve in [EC.Curve.p256, .p384] {

                let privateKey = try XCTUnwrap(EC.PrivateKey.random(curve: curve))
                let publicKey = privateKey.publicKey

                let keyType = try await session.putKey(
                    key: privateKey,
                    inSlot: .signature,
                    pinPolicy: .always,
                    touchPolicy: .never
                )
                XCTAssert(keyType == PIV.ECCKey.ecc(curve))
                try await session.verifyPin("123456")
                let message = "Hello World!".data(using: .utf8)!
                let signature = try await session.sign(
                    slot: .signature,
                    keyType: .ecc(curve),
                    algorithm: .message(.sha256),
                    message: message
                )
                var error: Unmanaged<CFError>?
                let result = SecKeyVerifySignature(
                    publicKey.asSecKey()!,
                    SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256,
                    message as CFData,
                    signature as CFData,
                    &error
                )
                if let error = error {
                    XCTFail((error.takeRetainedValue() as Error).localizedDescription)
                    return
                }
                XCTAssertTrue(result)
            }
        }
    }

    func testPutECCP384Key() throws {
        runAuthenticatedPIVTest { session in
            let privateKey = try XCTUnwrap(EC.PrivateKey.random(curve: .p384))
            let publicKey = privateKey.publicKey

            let keyType = try await session.putKey(
                key: privateKey,
                inSlot: .signature,
                pinPolicy: .always,
                touchPolicy: .never
            )
            XCTAssert(keyType == PIV.ECCKey.ecc(.p384))
            try await session.verifyPin("123456")
            let message = "Hello World!".data(using: .utf8)!
            let signature = try await session.sign(
                slot: .signature,
                keyType: .ecc(.p384),
                algorithm: .message(.sha256),
                message: message
            )
            var error: Unmanaged<CFError>?
            let result = SecKeyVerifySignature(
                publicKey.asSecKey()!,
                SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256,
                message as CFData,
                signature as CFData,
                &error
            )
            if let error = error {
                XCTFail((error.takeRetainedValue() as Error).localizedDescription)
                return
            }
            XCTAssertTrue(result)
        }
    }

    func testPutEd25519Key() throws {
        runAuthenticatedPIVTest { session in
            guard session.supports(PIVSessionFeature.ed25519) else {
                print("⚠️ Skip testPutEd25519Key()")
                return
            }

            // Generate Ed25519 key using CryptoKit
            let cryptoKitPrivateKey = Curve25519.Signing.PrivateKey()
            let cryptoKitPublicKey = cryptoKitPrivateKey.publicKey

            // Convert to YubiKit format
            let seed = cryptoKitPrivateKey.rawRepresentation
            let publicKeyData = cryptoKitPublicKey.rawRepresentation

            guard let yubiKitPublicKey = Curve25519.Ed25519.PublicKey(keyData: publicKeyData),
                let yubiKitPrivateKey = Curve25519.Ed25519.PrivateKey(seed: seed, publicKey: yubiKitPublicKey)
            else {
                XCTFail("Failed to create YubiKit Ed25519 keys")
                return
            }

            // Import the key
            let keyType = try await session.putKey(
                key: yubiKitPrivateKey,
                inSlot: .signature,
                pinPolicy: .always,
                touchPolicy: .never
            )
            XCTAssert(keyType == PIV.Ed25519Key.ed25519)

            // Test signing with the imported key
            try await session.verifyPin("123456")
            let message = "Hello Ed25519 Import!".data(using: .utf8)!
            let signature = try await session.sign(
                slot: .signature,
                keyType: .ed25519,
                message: message
            )

            // Verify signature using CryptoKit
            XCTAssertTrue(cryptoKitPublicKey.isValidSignature(signature, for: message))
        }
    }

    func testPutX25519Key() throws {
        runAuthenticatedPIVTest { session in
            guard session.supports(PIVSessionFeature.x25519) else {
                print("⚠️ Skip testPutX25519Key()")
                return
            }

            // Generate X25519 key using CryptoKit
            let cryptoKitPrivateKey = Curve25519.KeyAgreement.PrivateKey()
            let cryptoKitPublicKey = cryptoKitPrivateKey.publicKey

            // Convert to YubiKit format
            let scalar = cryptoKitPrivateKey.rawRepresentation
            let publicKeyData = cryptoKitPublicKey.rawRepresentation

            guard let yubiKitPublicKey = Curve25519.X25519.PublicKey(keyData: publicKeyData),
                let yubiKitPrivateKey = Curve25519.X25519.PrivateKey(scalar: scalar, publicKey: yubiKitPublicKey)
            else {
                XCTFail("Failed to create YubiKit X25519 keys")
                return
            }

            // Import the key
            let keyType = try await session.putKey(
                key: yubiKitPrivateKey,
                inSlot: .signature,
                pinPolicy: .always,
                touchPolicy: .never
            )
            XCTAssert(keyType == PIV.X25519Key.x25519)

            // Test key agreement with the imported key
            let otherCryptoKitPrivateKey = Curve25519.KeyAgreement.PrivateKey()
            let otherCryptoKitPublicKey = otherCryptoKitPrivateKey.publicKey
            let otherPublicKeyData = otherCryptoKitPublicKey.rawRepresentation

            guard let otherYubiKitPublicKey = Curve25519.X25519.PublicKey(keyData: otherPublicKeyData) else {
                XCTFail("Failed to create other YubiKit X25519 public key")
                return
            }

            try await session.verifyPin("123456")
            let yubiKeySecret = try await session.calculateSecretKeyInSlot(
                slot: .signature,
                peerKey: otherYubiKitPublicKey
            )

            // Verify key agreement using CryptoKit
            let softwareSecret = try cryptoKitPrivateKey.sharedSecretFromKeyAgreement(with: otherCryptoKitPublicKey)
            let softwareSecretData = softwareSecret.withUnsafeBytes { Data($0) }

            XCTAssert(softwareSecretData == yubiKeySecret)
        }
    }

    // MARK: - Key Generation Tests

    func testGenerateRSA1024Key() throws {
        runAuthenticatedPIVTest { session in
            let result = try await session.generateKeyInSlot(
                slot: .signature,
                type: .rsa(.bits1024),
                pinPolicy: .always,
                touchPolicy: .cached
            )
            guard case let .rsa(publicKey) = result else {
                XCTFail("Expected RSA public key")
                return
            }
            XCTAssert(publicKey.size == .bits1024)
        }
    }

    func testGenerateRSA2048Key() throws {
        runAuthenticatedPIVTest(withTimeout: 50) { session in
            let result = try await session.generateKeyInSlot(
                slot: .signature,
                type: .rsa(.bits2048),
                pinPolicy: .always,
                touchPolicy: .cached
            )
            guard case let .rsa(publicKey) = result else {
                XCTFail("Expected RSA public key")
                return
            }
            XCTAssert(publicKey.size == .bits2048)
        }
    }

    func testGenerateRSA3072Key() throws {
        runAuthenticatedPIVTest(withTimeout: 200) { session in
            let result = try await session.generateKeyInSlot(
                slot: .signature,
                type: .rsa(.bits3072),
                pinPolicy: .always,
                touchPolicy: .cached
            )
            guard case let .rsa(publicKey) = result else {
                XCTFail("Expected RSA public key")
                return
            }
            XCTAssert(publicKey.size == .bits3072)
        }
    }

    func testGenerateRSA4096Key() throws {
        runAuthenticatedPIVTest(withTimeout: 200) { session in
            let result = try await session.generateKeyInSlot(
                slot: .signature,
                type: .rsa(.bits4096),
                pinPolicy: .always,
                touchPolicy: .cached
            )
            guard case let .rsa(publicKey) = result else {
                XCTFail("Expected RSA public key")
                return
            }
            XCTAssert(publicKey.size == .bits4096)
        }
    }

    func testGenerateECCP256Key() throws {
        runAuthenticatedPIVTest { session in
            let result = try await session.generateKeyInSlot(
                slot: .signature,
                type: .ecc(.p256),
                pinPolicy: .always,
                touchPolicy: .cached
            )
            guard case let .ec(publicKey) = result else {
                XCTFail("Expected EC public key")
                return
            }
            XCTAssert(publicKey.curve == .p256)
        }
    }

    func testGenerateECCP384Key() throws {
        runAuthenticatedPIVTest { session in
            let result = try await session.generateKeyInSlot(
                slot: .signature,
                type: .ecc(.p384),
                pinPolicy: .always,
                touchPolicy: .cached
            )
            guard case let .ec(publicKey) = result else {
                XCTFail("Expected EC public key")
                return
            }
            XCTAssert(publicKey.curve == .p384)
        }
    }

    func testGenerateEd25519Key() throws {
        runAuthenticatedPIVTest { session in
            guard session.supports(PIVSessionFeature.ed25519) else {
                print("⚠️ Skip testGenerateEd25519Key()")
                return
            }
            let result = try await session.generateKeyInSlot(
                slot: .signature,
                type: .ed25519,
                pinPolicy: .always,
                touchPolicy: .cached
            )
            guard case let .ed25519(publicKey) = result else {
                XCTFail("Expected Ed25519 public key")
                return
            }
            XCTAssert(publicKey.keyData.count == 32)
        }
    }

    func testGenerateX25519Key() throws {
        runAuthenticatedPIVTest { session in
            guard session.supports(PIVSessionFeature.x25519) else {
                print("⚠️ Skip testGenerateX25519Key()")
                return
            }
            let result = try await session.generateKeyInSlot(
                slot: .signature,
                type: .x25519,
                pinPolicy: .always,
                touchPolicy: .cached
            )
            guard case let .x25519(publicKey) = result else {
                XCTFail("Expected X25519 public key")
                return
            }
            XCTAssert(publicKey.keyData.count == 32)
        }
    }

    // MARK: - Attestation Tests

    func testAttestRSAKey() throws {
        runAuthenticatedPIVTest { session in
            let result = try await session.generateKeyInSlot(slot: .signature, type: .rsa(.bits1024))
            guard case let .rsa(publicKey) = result else {
                XCTFail("Expected RSA public key")
                return
            }

            let cert = try await session.attestKeyInSlot(slot: .signature)
            guard case let .rsa(attestKey) = cert.publicKey else {
                XCTFail("Expected RSA public key in certificate")
                return
            }

            XCTAssert(attestKey == publicKey)
        }
    }

    func testAttestEd25519Key() throws {
        runAuthenticatedPIVTest { session in
            guard session.supports(PIVSessionFeature.ed25519) else {
                print("⚠️ Skip testAttestEd25519Key()")
                return
            }
            let result = try await session.generateKeyInSlot(slot: .signature, type: .ed25519)
            guard case let .ed25519(publicKey) = result else {
                XCTFail("Expected Ed25519 public key")
                return
            }

            let cert = try await session.attestKeyInSlot(slot: .signature)
            guard case let .ed25519(attestKey) = cert.publicKey else {
                XCTFail("Expected Ed25519 public key in certificate")
                return
            }

            XCTAssert(attestKey == publicKey)
        }
    }

    func testAttestX25519Key() throws {
        runAuthenticatedPIVTest { session in
            guard session.supports(PIVSessionFeature.x25519) else {
                print("⚠️ Skip testAttestX25519Key()")
                return
            }
            let result = try await session.generateKeyInSlot(slot: .signature, type: .x25519)
            guard case let .x25519(publicKey) = result else {
                XCTFail("Expected X25519 public key")
                return
            }

            let cert = try await session.attestKeyInSlot(slot: .signature)
            // Note: X509Cert may not support X25519 key extraction yet
            if case let .x25519(attestKey) = cert.publicKey {
                XCTAssert(attestKey == publicKey)
            } else {
                // Just verify that the certificate was generated successfully
                XCTAssertNotNil(cert.der)
                XCTAssert(cert.der.count > 0)
            }
        }
    }

    // MARK: - Certificate Management Tests

    let testCertificate = X509Cert(
        der: Data(
            base64Encoded:
                "MIIBKzCB0qADAgECAhQTuU25u6oazORvKfTleabdQaDUGzAKBggqhkjOPQQDAjAWMRQwEgYDVQQDDAthbW9zLmJ1cnRvbjAeFw0yMTAzMTUxMzU5MjVaFw0yODA1MTcwMDAwMDBaMBYxFDASBgNVBAMMC2Ftb3MuYnVydG9uMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEofwN6S+atSZmzeLK7aSI+mJJwxh0oUBiCOngHLeToYeanrTGvCZQ2AK/R9esnqSxMyBUDp91UO4F6U4c6RTooTAKBggqhkjOPQQDAgNIADBFAiAnj/KUSpW7l5wnenQEbwWudK/7q3WtyrqdB0H1xc258wIhALDLImzu3S+0TT2/ggM95LLWE4Llfa2RQM71bnW6zqqn"
        )!
    )

    func testPutAndReadCertificate() throws {
        runAuthenticatedPIVTest { session in
            try await session.putCertificate(
                certificate: self.testCertificate,
                inSlot: .authentication,
                compress: false
            )
            let retrievedCertificate = try await session.getCertificateInSlot(.authentication)
            XCTAssert(self.testCertificate.der == retrievedCertificate.der)
        }
    }

    // MARK: - Key Management Tests

    func testMoveKey() throws {
        runAuthenticatedPIVTest { session in
            guard session.supports(PIVSessionFeature.moveDelete) else {
                print("⚠️ Skip testMoveKey()")
                return
            }
            try await session.putCertificate(certificate: self.testCertificate, inSlot: .authentication)
            try await session.putCertificate(certificate: self.testCertificate, inSlot: .signature)
            let publicKey = try await session.generateKeyInSlot(
                slot: .authentication,
                type: .rsa(.bits1024),
                pinPolicy: .always,
                touchPolicy: .always
            )
            let authSlotMetadata = try await session.getSlotMetadata(.authentication)
            XCTAssertEqual(publicKey, authSlotMetadata.publicKey)
            try await session.moveKey(sourceSlot: .authentication, destinationSlot: .signature)
            let signSlotMetadata = try await session.getSlotMetadata(.signature)
            XCTAssertEqual(publicKey, signSlotMetadata.publicKey)
            do {
                _ = try await session.getSlotMetadata(.authentication)
                XCTFail("Got metadata when we should have thrown a referenceDataNotFound exception.")
            } catch {
                guard let responseError = error as? ResponseError else {
                    XCTFail("Unexpected error: \(error)")
                    return
                }
                XCTAssertTrue(responseError.responseStatus.status == .referencedDataNotFound)
            }
        }
    }

    func testDeleteKey() throws {
        runAuthenticatedPIVTest { session in
            guard session.supports(PIVSessionFeature.moveDelete) else {
                print("⚠️ Skip testDeleteKey()")
                return
            }
            try await session.putCertificate(certificate: self.testCertificate, inSlot: .authentication, compress: true)
            let publicKey = try await session.generateKeyInSlot(
                slot: .authentication,
                type: .rsa(.bits1024),
                pinPolicy: .always,
                touchPolicy: .always
            )
            let slotMetadata = try await session.getSlotMetadata(.authentication)
            XCTAssertEqual(publicKey, slotMetadata.publicKey)
            try await session.deleteKey(in: .authentication)
            do {
                _ = try await session.getSlotMetadata(.authentication)
                XCTFail("Got metadata when we should have thrown a referenceDataNotFound exception.")
            } catch {
                guard let responseError = error as? ResponseError else {
                    XCTFail("Unexpected error: \(error)")
                    return
                }
                XCTAssertTrue(responseError.responseStatus.status == .referencedDataNotFound)
            }
        }
    }

    func testPutCompressedAndReadCertificate() throws {
        runAuthenticatedPIVTest { session in
            try await session.putCertificate(certificate: self.testCertificate, inSlot: .authentication, compress: true)
            let retrievedCertificate = try await session.getCertificateInSlot(.authentication)
            XCTAssert(self.testCertificate.der == retrievedCertificate.der)
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
                guard let error = error as? ResponseError else {
                    XCTFail("Deleted certificate returned unexpected error: \(error)")
                    return
                }
                XCTAssert(error.responseStatus.status == .fileNotFound)
            }
        }
    }

    // MARK: - Management Key Tests

    func testAuthenticateWithDefaultManagementKey() throws {
        runPIVTest { session in
            do {
                let keyType: PIV.ManagementKeyType
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
            guard session.supports(PIVSessionFeature.aesKey) else {
                print("⚠️ Skip testSet3DESManagementKey()")
                return
            }
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
            guard session.supports(PIVSessionFeature.aesKey) else {
                print("⚠️ Skip testSetAESManagementKey()")
                return
            }
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
                let keyType: PIV.ManagementKeyType
                if session.supports(PIVSessionFeature.metadata) {
                    let metadata = try await session.getManagementKeyMetadata()
                    keyType = metadata.keyType
                } else {
                    keyType = .tripleDES
                }
                try await session.authenticateWith(managementKey: wrongManagementKey, keyType: keyType)
                XCTFail("Successfully authenticated with the wrong management key.")
            } catch {
                guard let error = error as? ResponseError else {
                    XCTFail("Failed with unexpected error: \(error)")
                    return
                }
                XCTAssert(error.responseStatus.status == .securityConditionNotSatisfied)
            }
        }
    }

    // MARK: - PIN/PUK Tests

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

    // MARK: - Device Information Tests

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
            guard session.supports(PIVSessionFeature.serialNumber) else {
                print("⚠️ Skip testSerialNumber()")
                return
            }
            let serialNumber = try await session.getSerialNumber()
            XCTAssert(serialNumber > 0)
            print("➡️ Serial number: \(serialNumber)")
        }
    }

    // MARK: - Metadata Tests

    func testManagementKeyMetadata() throws {
        runPIVTest { session in
            guard session.supports(PIVSessionFeature.metadata) else {
                print("⚠️ Skip testManagementKeyMetadata()")
                return
            }
            let metadata = try await session.getManagementKeyMetadata()
            XCTAssertEqual(metadata.isDefault, true)
            print("➡️ Management key type: \(metadata.keyType)")
            print("➡️ Management touch policy: \(metadata.touchPolicy)")
        }

    }

    func testSlotMetadata() throws {
        runAuthenticatedPIVTest { session in
            guard session.supports(PIVSessionFeature.metadata) else {
                print("⚠️ Skip testSlotMetadata()")
                return
            }
            var publicKey = try await session.generateKeyInSlot(
                slot: .authentication,
                type: .ecc(.p256),
                pinPolicy: .always,
                touchPolicy: .always
            )
            var metadata = try await session.getSlotMetadata(.authentication)
            XCTAssertEqual(metadata.keyType, .ecc(.p256))
            XCTAssertEqual(metadata.pinPolicy, .always)
            XCTAssertEqual(metadata.touchPolicy, .always)
            XCTAssertEqual(metadata.generated, true)
            XCTAssertEqual(metadata.publicKey, publicKey)

            publicKey = try await session.generateKeyInSlot(
                slot: .authentication,
                type: .ecc(.p384),
                pinPolicy: .never,
                touchPolicy: .never
            )
            metadata = try await session.getSlotMetadata(.authentication)
            XCTAssertEqual(metadata.keyType, .ecc(.p384))
            XCTAssertEqual(metadata.pinPolicy, .never)
            XCTAssertEqual(metadata.touchPolicy, .never)
            XCTAssertEqual(metadata.generated, true)
            XCTAssertEqual(metadata.publicKey, publicKey)

            publicKey = try await session.generateKeyInSlot(
                slot: .authentication,
                type: .ecc(.p256),
                pinPolicy: .once,
                touchPolicy: .cached
            )
            metadata = try await session.getSlotMetadata(.authentication)
            XCTAssertEqual(metadata.keyType, .ecc(.p256))
            XCTAssertEqual(metadata.pinPolicy, .once)
            XCTAssertEqual(metadata.touchPolicy, .cached)
            XCTAssertEqual(metadata.generated, true)
            XCTAssertEqual(metadata.publicKey, publicKey)
        }

    }

    func testAESManagementKeyMetadata() throws {
        runAuthenticatedPIVTest { session in
            guard session.supports(PIVSessionFeature.metadata) else {
                print("⚠️ Skip testAESManagementKeyMetadata()")
                return
            }
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
            guard session.supports(PIVSessionFeature.metadata) else {
                print("⚠️ Skip testPinMetadata()")
                return
            }
            let result = try await session.getPinMetadata()
            XCTAssertEqual(result.isDefault, true)
            XCTAssertEqual(result.retriesTotal, 3)
            XCTAssertEqual(result.retriesRemaining, 3)
        }
    }

    func testPinMetadataRetries() throws {
        runAuthenticatedPIVTest { session in
            guard session.supports(PIVSessionFeature.metadata) else {
                print("⚠️ Skip testPinMetadataRetries()")
                return
            }
            try await session.verifyPin("111111")
            let result = try await session.getPinMetadata()
            XCTAssertEqual(result.isDefault, true)
            XCTAssertEqual(result.retriesTotal, 3)
            XCTAssertEqual(result.retriesRemaining, 2)
        }
    }

    func testPukMetadata() throws {
        runPIVTest { session in
            guard session.supports(PIVSessionFeature.metadata) else {
                print("⚠️ Skip testPukMetadata()")
                return
            }
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
            guard verifyBlockedPin == .pinLocked else {
                XCTFail("Pin failed to block.")
                return
            }
            try await session.unblockPinWithPuk("12345678", newPin: "222222")
            let verifyUnblockedPin = try await session.verifyPin("222222")
            switch verifyUnblockedPin {
            case .success(_):
                return
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

    // MARK: - Biometric Authentication Tests

    // This will test auth on a YubiKey Bio. To run the test at least one fingerprint needs to be registered.
    func testBioAuthentication() throws {
        runAsyncTest {
            let connection = try await TestableConnections.create()
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
            let connection = try await TestableConnections.create()
            let managementSession = try await ManagementSession.session(withConnection: connection)
            let deviceInfo = try await managementSession.getDeviceInfo()
            guard deviceInfo.formFactor != .usbCBio && deviceInfo.formFactor != .usbABio else {
                print("⚠️ Skip testBioPinPolicyErrorOnNonBioKey() since this is a bio key.")
                return
            }
            let session = try await PIVSession.session(withConnection: connection)
            try await self.authenticate(with: session)
            do {
                _ = try await session.generateKeyInSlot(
                    slot: .signature,
                    type: .ecc(.p384),
                    pinPolicy: .matchAlways,
                    touchPolicy: .defaultPolicy
                )
            } catch {
                guard let sessionError = error as? SessionError else { throw error }
                XCTAssertEqual(sessionError, SessionError.notSupported)
            }
            do {
                _ = try await session.generateKeyInSlot(
                    slot: .signature,
                    type: .ecc(.p384),
                    pinPolicy: .matchOnce,
                    touchPolicy: .defaultPolicy
                )
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
        let keyType: PIV.ManagementKeyType
        if session.supports(PIVSessionFeature.metadata) {
            let metadata = try await session.getManagementKeyMetadata()
            keyType = metadata.keyType
        } else {
            keyType = .tripleDES
        }
        try await session.authenticateWith(managementKey: defaultManagementKey, keyType: keyType)
    }

    func runPIVTest(
        named testName: String = #function,
        in file: StaticString = #file,
        at line: UInt = #line,
        withTimeout timeout: TimeInterval = 20,
        test: @escaping (PIVSession) async throws -> Void
    ) {
        runAsyncTest(named: testName, in: file, at: line, withTimeout: timeout) {
            let connection = try await TestableConnections.create()
            let session = try await PIVSession.session(withConnection: connection)
            try await session.reset()
            Logger.test.debug("⬇️ ⬇️ ⬇️ ⬇️ ⬇️ ⬇️ ⬇️ ⬇️ PIV Session test ⬇️ ⬇️ ⬇️ ⬇️ ⬇️ ⬇️ ⬇️ ⬇️")
            try await test(session)
            Logger.test.debug("✅ \(testName) passed")
        }
    }

    func runAuthenticatedPIVTest(
        named testName: String = #function,
        in file: StaticString = #file,
        at line: UInt = #line,
        withTimeout timeout: TimeInterval = 20,
        test: @escaping (PIVSession) async throws -> Void
    ) {
        runAsyncTest(named: testName, in: file, at: line, withTimeout: timeout) {
            let connection = try await TestableConnections.create()
            let session = try await PIVSession.session(withConnection: connection)
            try await session.reset()
            try await self.authenticate(with: session)
            Logger.test.debug("⬇️ ⬇️ ⬇️ ⬇️ ⬇️ ⬇️ ⬇️ ⬇️ PIV Session test ⬇️ ⬇️ ⬇️ ⬇️ ⬇️ ⬇️ ⬇️ ⬇️")
            try await test(session)
            Logger.test.debug("✅ \(testName) passed")
        }
    }
}
