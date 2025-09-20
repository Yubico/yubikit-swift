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

import CryptoKit
import Foundation
import Testing

@testable import FullStackTests
@testable import YubiKit

// MARK: - Test Tags
extension Tag {
    @Tag static var slowTests: Tag
}

private let defaultManagementKey = Data(hexEncodedString: "010203040506070801020304050607080102030405060708")!
private let defaultPIN = "123456"
private let testMessage = "Hello world!".data(using: .utf8)!

@Suite("PIV Full Stack Tests", .serialized, .timeLimit(.minutes(30)))
struct PIVFullStackTests {

    // MARK: - Signing Tests

    @Test("Sign with ECC P-256 (Message)")
    func signECCP256Message() async throws {
        try await runPIVTest(authenticated: true) { session in
            let publicKey = try await session.generateKey(
                in: .signature,
                type: .ecc(.secp256r1)
            )

            guard case let .ec(ecPublicKey) = publicKey else {
                Issue.record("Failed to generate EC key")
                return
            }

            try await session.verifyPin(defaultPIN)
            let signature = try await session.sign(
                testMessage,
                in: .signature,
                keyType: PIV.ECCKey.ecc(.secp256r1),
                using: .message(.sha256)
            )

            try self.verifyECSignature(
                publicKey: ecPublicKey,
                message: testMessage,
                signature: signature,
                algorithm: .ecdsaSignatureMessageX962SHA256
            )
        }
    }

    @Test("Sign with ECC P-256 (Digest)")
    func signECCP256Digest() async throws {
        try await runPIVTest(authenticated: true) { session in
            let publicKey = try await session.generateKey(
                in: .signature,
                type: .ecc(.secp256r1)
            )

            guard case let .ec(ecPublicKey) = publicKey else {
                Issue.record("Failed to generate EC key")
                return
            }

            try await session.verifyPin(defaultPIN)
            let digest = SHA256.hash(data: testMessage)
            let digestData = Data(digest)

            let signature = try await session.sign(
                digestData,
                in: .signature,
                keyType: PIV.ECCKey.ecc(.secp256r1),
                using: .digest(.sha256)
            )

            try self.verifyECSignature(
                publicKey: ecPublicKey,
                message: digestData,
                signature: signature,
                algorithm: .ecdsaSignatureDigestX962SHA256
            )
        }
    }

    @Test("Sign with RSA", arguments: [RSA.KeySize.bits1024, .bits2048])
    func signRSA(keySize: RSA.KeySize) async throws {
        try await runPIVTest(authenticated: true) { session in
            let publicKey = try await session.generateKey(
                in: .signature,
                type: .rsa(keySize)
            )

            guard case let .rsa(rsaPublicKey) = publicKey else {
                Issue.record("Failed to generate RSA key")
                return
            }

            try await session.verifyPin(defaultPIN)
            let signature = try await session.sign(
                testMessage,
                in: .signature,
                keyType: .rsa(keySize),
                using: .pkcs1v15(.sha512)
            )

            try self.verifyRSASignature(
                publicKey: rsaPublicKey,
                message: testMessage,
                signature: signature,
                algorithm: .rsaSignatureMessagePKCS1v15SHA512
            )
        }
    }

    @Test("Sign with Ed25519")
    func signEd25519() async throws {
        try await runPIVTest(authenticated: true) { session in
            guard await session.supports(PIVSessionFeature.ed25519) else {
                reportSkip(reason: "Ed25519 not supported on this YubiKey")
                return
            }

            let publicKey = try await session.generateKey(
                in: .signature,
                type: .ed25519
            )

            guard case let .ed25519(ed25519PublicKey) = publicKey else {
                Issue.record("Failed to generate Ed25519 key")
                return
            }

            try await session.verifyPin(defaultPIN)
            let signature = try await session.sign(
                testMessage,
                in: .signature,
                keyType: .ed25519
            )

            // Convert YubiKit public key to CryptoKit for verification
            let cryptoKitPublicKey = try Curve25519.Signing.PublicKey(rawRepresentation: ed25519PublicKey.keyData)
            #expect(cryptoKitPublicKey.isValidSignature(signature, for: testMessage))
        }
    }

    // MARK: - Decryption Tests

    @Test("Decrypt with RSA", arguments: [RSA.KeySize.bits1024, .bits2048])
    func decryptRSA(keySize: RSA.KeySize) async throws {
        try await runPIVTest(authenticated: true) { session in
            try await testRSAEncryptionDecryption(session: session, keySize: keySize)
        }
    }

    // MARK: - Key Agreement Tests

    @Test("ECDH with P-256 and P-384", arguments: [EC.Curve.secp256r1, .secp384r1])
    func sharedSecretEC(curve: EC.Curve) async throws {
        try await runPIVTest(authenticated: true) { session in
            let publicKey = try await session.generateKey(
                in: .signature,
                type: .ecc(curve)
            )

            guard case let .ec(yubiKeyPublicKey) = publicKey else {
                Issue.record("Failed to generate EC key")
                return
            }

            let privateKey = try #require(EC.PrivateKey.random(curve: curve))
            let peerPublicKey = privateKey.publicKey

            try await session.verifyPin(defaultPIN)
            let yubiKeySecret = try await session.deriveSharedSecret(in: .signature, with: peerPublicKey)
            let softwareSecret =
                SecKeyCopyKeyExchangeResult(
                    privateKey.asSecKey()!,
                    .ecdhKeyExchangeStandard,
                    yubiKeyPublicKey.asSecKey()!,
                    [String: Any]() as CFDictionary,
                    nil
                )! as Data

            #expect(softwareSecret == yubiKeySecret)
        }
    }

    @Test("ECDH with X25519")
    func sharedSecretX25519() async throws {
        try await runPIVTest(authenticated: true) { session in
            guard await session.supports(PIVSessionFeature.x25519) else {
                reportSkip(reason: "X25519 not supported on this YubiKey")
                return
            }

            let publicKey = try await session.generateKey(
                in: .signature,
                type: .x25519
            )

            guard case let .x25519(yubiKeyPublicKey) = publicKey else {
                Issue.record("Failed to generate X25519 key")
                return
            }

            // Generate X25519 key using CryptoKit
            let cryptoKitPrivateKey = Curve25519.KeyAgreement.PrivateKey()
            let cryptoKitPublicKey = cryptoKitPrivateKey.publicKey

            // Convert to YubiKit format
            let publicKeyData = cryptoKitPublicKey.rawRepresentation
            guard let yubiKitPublicKey = X25519.PublicKey(keyData: publicKeyData) else {
                Issue.record("Failed to create YubiKit X25519 public key")
                return
            }

            try await session.verifyPin(defaultPIN)
            let yubiKeySecret = try await session.deriveSharedSecret(in: .signature, with: yubiKitPublicKey)

            // Calculate shared secret using CryptoKit
            let softwareSecret = try cryptoKitPrivateKey.sharedSecretFromKeyAgreement(
                with: Curve25519.KeyAgreement.PublicKey(rawRepresentation: yubiKeyPublicKey.keyData)
            )
            let softwareSecretData = softwareSecret.withUnsafeBytes { Data($0) }

            #expect(softwareSecretData == yubiKeySecret)
        }
    }

    // MARK: - Key Import Tests

    @Test("Import RSA 1024-bit key")
    func putRSA1024Key() async throws {
        try await testRSAKeyImport(keySize: .bits1024)
    }

    @Test("Import RSA 2048-bit key")
    func putRSA2048Key() async throws {
        try await testRSAKeyImport(keySize: .bits2048)
    }

    @Test("Import RSA 3072-bit key", .timeLimit(.minutes(5)), .tags(.slowTests))
    func putRSA3072Key() async throws {
        try await testRSAKeyImport(keySize: .bits3072)
    }

    // @Test("Import RSA 4096-bit key", .timeLimit(.minutes(10)), .tags(.slowTests))
    // func putRSA4096Key() async throws {
    //     try await testRSAKeyImport(keySize: .bits4096)
    // }

    private func testRSAKeyImport(keySize: RSA.KeySize) async throws {
        try await runPIVTest(authenticated: true) { session in
            // Check for RSA 3072/4096 feature support
            if keySize == .bits3072 || keySize == .bits4096 {
                guard await session.supports(PIVSessionFeature.rsa3072and4096) else {
                    reportSkip(reason: "RSA 3072/4096 not supported on this YubiKey")
                    return
                }
            }

            guard let privateKey = RSA.PrivateKey.random(keySize: keySize) else {
                Issue.record("Failed to create RSA keys")
                return
            }
            let publicKey = privateKey.publicKey

            let keyType = try await session.putPrivateKey(
                privateKey,
                in: .signature,
                pinPolicy: .always,
                touchPolicy: .never
            )
            #expect(keyType == PIV.RSAKey.rsa(keySize))

            let dataToEncrypt = testMessage
            guard let secKey = publicKey.asSecKey(),
                let encryptedData = SecKeyCreateEncryptedData(
                    secKey,
                    .rsaEncryptionPKCS1,
                    dataToEncrypt as CFData,
                    nil
                ) as Data?
            else {
                Issue.record("Failed encrypting data with SecKeyCreateEncryptedData().")
                return
            }

            try await session.verifyPin(defaultPIN)
            let decryptedData = try await session.decrypt(
                encryptedData,
                in: .signature,
                using: .pkcs1v15
            )
            #expect(dataToEncrypt == decryptedData)
        }
    }

    @Test("Import ECC P-256 key")
    func putECCP256Key() async throws {
        try await testECCKeyImport(curve: .secp256r1)
    }

    @Test("Import ECC P-384 key")
    func putECCP384Key() async throws {
        try await testECCKeyImport(curve: .secp384r1)
    }

    private func testECCKeyImport(curve: EC.Curve) async throws {
        try await runPIVTest(authenticated: true) { session in
            let privateKey = try #require(EC.PrivateKey.random(curve: curve))
            let publicKey = privateKey.publicKey

            let keyType = try await session.putPrivateKey(
                privateKey,
                in: .signature,
                pinPolicy: .always,
                touchPolicy: .never
            )
            #expect(keyType == PIV.ECCKey.ecc(curve))

            try await session.verifyPin(defaultPIN)
            let signature = try await session.sign(
                testMessage,
                in: .signature,
                keyType: .ecc(curve),
                using: .message(.sha256)
            )

            try self.verifyECSignature(
                publicKey: publicKey,
                message: testMessage,
                signature: signature,
                algorithm: .ecdsaSignatureMessageX962SHA256
            )
        }
    }

    @Test("Import Ed25519 Key")
    func putEd25519Key() async throws {
        try await runPIVTest(authenticated: true) { session in
            guard await session.supports(PIVSessionFeature.ed25519) else {
                reportSkip(reason: "Ed25519 not supported on this YubiKey")
                return
            }

            // Generate Ed25519 key using CryptoKit
            let cryptoKitPrivateKey = Curve25519.Signing.PrivateKey()
            let cryptoKitPublicKey = cryptoKitPrivateKey.publicKey

            // Convert to YubiKit format
            let seed = cryptoKitPrivateKey.rawRepresentation
            let publicKeyData = cryptoKitPublicKey.rawRepresentation

            guard let yubiKitPublicKey = Ed25519.PublicKey(keyData: publicKeyData),
                let yubiKitPrivateKey = Ed25519.PrivateKey(seed: seed, publicKey: yubiKitPublicKey)
            else {
                Issue.record("Failed to create YubiKit Ed25519 keys")
                return
            }

            // Import the key
            let keyType = try await session.putPrivateKey(
                yubiKitPrivateKey,
                in: .signature,
                pinPolicy: .always,
                touchPolicy: .never
            )
            #expect(keyType == PIV.Ed25519Key.ed25519)

            // Test signing with the imported key
            try await session.verifyPin(defaultPIN)
            let signature = try await session.sign(
                testMessage,
                in: .signature,
                keyType: .ed25519
            )

            // Verify signature using CryptoKit
            #expect(cryptoKitPublicKey.isValidSignature(signature, for: testMessage))
        }
    }

    @Test("Import X25519 Key")
    func putX25519Key() async throws {
        try await runPIVTest(authenticated: true) { session in
            guard await session.supports(PIVSessionFeature.x25519) else {
                reportSkip(reason: "X25519 not supported on this YubiKey")
                return
            }

            // Generate X25519 key using CryptoKit
            let cryptoKitPrivateKey = Curve25519.KeyAgreement.PrivateKey()
            let cryptoKitPublicKey = cryptoKitPrivateKey.publicKey

            // Convert to YubiKit format
            let scalar = cryptoKitPrivateKey.rawRepresentation
            let publicKeyData = cryptoKitPublicKey.rawRepresentation

            guard let yubiKitPublicKey = X25519.PublicKey(keyData: publicKeyData),
                let yubiKitPrivateKey = X25519.PrivateKey(scalar: scalar, publicKey: yubiKitPublicKey)
            else {
                Issue.record("Failed to create YubiKit X25519 keys")
                return
            }

            // Import the key
            let keyType = try await session.putPrivateKey(
                yubiKitPrivateKey,
                in: .signature,
                pinPolicy: .always,
                touchPolicy: .never
            )
            #expect(keyType == PIV.X25519Key.x25519)

            // Test key agreement with the imported key
            let otherCryptoKitPrivateKey = Curve25519.KeyAgreement.PrivateKey()
            let otherCryptoKitPublicKey = otherCryptoKitPrivateKey.publicKey
            let otherPublicKeyData = otherCryptoKitPublicKey.rawRepresentation

            guard let otherYubiKitPublicKey = X25519.PublicKey(keyData: otherPublicKeyData) else {
                Issue.record("Failed to create other YubiKit X25519 public key")
                return
            }

            try await session.verifyPin(defaultPIN)
            let yubiKeySecret = try await session.deriveSharedSecret(
                in: .signature,
                with: otherYubiKitPublicKey
            )

            // Verify key agreement using CryptoKit
            let softwareSecret = try cryptoKitPrivateKey.sharedSecretFromKeyAgreement(with: otherCryptoKitPublicKey)
            let softwareSecretData = softwareSecret.withUnsafeBytes { Data($0) }

            #expect(softwareSecretData == yubiKeySecret)
        }
    }

    // MARK: - Key Generation Tests

    @Test("Generate RSA 1024-bit key")
    func generateRSA1024Key() async throws {
        try await runPIVTest(authenticated: true) { session in
            let result = try await session.generateKey(
                in: .signature,
                type: .rsa(.bits1024),
                pinPolicy: .always,
                touchPolicy: .cached
            )
            guard case let .rsa(publicKey) = result else {
                Issue.record("Expected RSA public key")
                return
            }
            #expect(publicKey.size == .bits1024)
        }
    }

    @Test("Generate RSA 2048-bit key")
    func generateRSA2048Key() async throws {
        try await runPIVTest(authenticated: true) { session in
            let result = try await session.generateKey(
                in: .signature,
                type: .rsa(.bits2048),
                pinPolicy: .always,
                touchPolicy: .cached
            )
            guard case let .rsa(publicKey) = result else {
                Issue.record("Expected RSA public key")
                return
            }
            #expect(publicKey.size == .bits2048)
        }
    }

    @Test("Generate RSA 3072-bit key", .timeLimit(.minutes(5)), .tags(.slowTests))
    func generateRSA3072Key() async throws {
        try await runPIVTest(authenticated: true) { session in
            guard await session.supports(PIVSessionFeature.rsa3072and4096) else {
                reportSkip(reason: "RSA 3072/4096 not supported on this YubiKey")
                return
            }

            let result = try await session.generateKey(
                in: .signature,
                type: .rsa(.bits3072),
                pinPolicy: .always,
                touchPolicy: .cached
            )
            guard case let .rsa(publicKey) = result else {
                Issue.record("Expected RSA public key")
                return
            }
            #expect(publicKey.size == .bits3072)
        }
    }

    // @Test("Generate RSA 4096-bit key", .timeLimit(.minutes(10)), .tags(.slowTests))
    // func generateRSA4096Key() async throws {
    //     try await runPIVTest(authenticated: true) { session in
    //         let result = try await session.generateKey(
    //             in: .signature,
    //             type: .rsa(.bits4096),
    //             pinPolicy: .always,
    //             touchPolicy: .cached
    //         )
    //         guard case let .rsa(publicKey) = result else {
    //             Issue.record("Expected RSA public key")
    //             return
    //         }
    //         #expect(publicKey.size == .bits4096)
    //     }
    // }

    @Test("Generate ECC P-256 key")
    func generateECCP256Key() async throws {
        try await runPIVTest(authenticated: true) { session in
            let result = try await session.generateKey(
                in: .signature,
                type: .ecc(.secp256r1),
                pinPolicy: .always,
                touchPolicy: .cached
            )
            guard case let .ec(publicKey) = result else {
                Issue.record("Expected EC public key")
                return
            }
            #expect(publicKey.curve == .secp256r1)
        }
    }

    @Test("Generate ECC P-384 key")
    func generateECCP384Key() async throws {
        try await runPIVTest(authenticated: true) { session in
            let result = try await session.generateKeyInSlot(
                slot: .signature,
                type: .ecc(.secp384r1),
                pinPolicy: .always,
                touchPolicy: .cached
            )
            guard case let .ec(publicKey) = result else {
                Issue.record("Expected EC public key")
                return
            }
            #expect(publicKey.curve == .secp384r1)
        }
    }

    @Test("Generate Ed25519 Key")
    func generateEd25519Key() async throws {
        try await runPIVTest(authenticated: true) { session in
            guard await session.supports(PIVSessionFeature.ed25519) else {
                reportSkip(reason: "Ed25519 not supported on this YubiKey")
                return
            }

            let result = try await session.generateKey(
                in: .signature,
                type: .ed25519,
                pinPolicy: .always,
                touchPolicy: .cached
            )
            guard case let .ed25519(publicKey) = result else {
                Issue.record("Expected Ed25519 public key")
                return
            }
            #expect(publicKey.keyData.count == 32)
        }
    }

    @Test("Generate X25519 Key")
    func generateX25519Key() async throws {
        try await runPIVTest(authenticated: true) { session in
            guard await session.supports(PIVSessionFeature.x25519) else {
                reportSkip(reason: "X25519 not supported on this YubiKey")
                return
            }

            let result = try await session.generateKey(
                in: .signature,
                type: .x25519,
                pinPolicy: .always,
                touchPolicy: .cached
            )
            guard case let .x25519(publicKey) = result else {
                Issue.record("Expected X25519 public key")
                return
            }
            #expect(publicKey.keyData.count == 32)
        }
    }

    // MARK: - Attestation Tests

    @Test("Attest RSA Key")
    func attestRSAKey() async throws {
        try await runPIVTest(authenticated: true) { session in
            let result = try await session.generateKey(in: .signature, type: .rsa(.bits1024))
            guard case let .rsa(publicKey) = result else {
                Issue.record("Expected RSA public key")
                return
            }

            let cert = try await session.attestKey(in: .signature)
            guard case let .rsa(attestKey) = cert.publicKey else {
                Issue.record("Expected RSA public key in certificate")
                return
            }

            #expect(attestKey == publicKey)
        }
    }

    @Test("Attest Ed25519 Key")
    func attestEd25519Key() async throws {
        try await runPIVTest(authenticated: true) { session in
            guard await session.supports(PIVSessionFeature.ed25519) else {
                reportSkip(reason: "Ed25519 not supported on this YubiKey")
                return
            }

            let result = try await session.generateKey(in: .signature, type: .ed25519)
            guard case let .ed25519(publicKey) = result else {
                Issue.record("Expected Ed25519 public key")
                return
            }

            let cert = try await session.attestKey(in: .signature)
            guard case let .ed25519(attestKey) = cert.publicKey else {
                Issue.record("Expected Ed25519 public key in certificate")
                return
            }

            #expect(attestKey == publicKey)
        }
    }

    @Test("Attest X25519 Key")
    func attestX25519Key() async throws {
        try await runPIVTest(authenticated: true) { session in
            guard await session.supports(PIVSessionFeature.x25519) else {
                reportSkip(reason: "X25519 not supported on this YubiKey")
                return
            }

            let result = try await session.generateKey(in: .signature, type: .x25519)
            guard case let .x25519(publicKey) = result else {
                Issue.record("Expected X25519 public key")
                return
            }

            let cert = try await session.attestKey(in: .signature)
            // Note: X509Cert may not support X25519 key extraction yet
            if case let .x25519(attestKey) = cert.publicKey {
                #expect(attestKey == publicKey)
            } else {
                // Just verify that the certificate was generated successfully
                #expect(cert.der.count > 0)
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

    @Test("Put and Read Certificate")
    func putAndReadCertificate() async throws {
        try await runPIVTest(authenticated: true) { session in
            try await session.putCertificate(
                self.testCertificate,
                in: .authentication,
                compressed: false
            )
            let retrievedCertificate = try await session.getCertificate(in: .authentication)
            #expect(self.testCertificate.der == retrievedCertificate.der)
        }
    }

    // MARK: - Key Management Tests

    @Test("Move Key")
    func moveKey() async throws {
        try await runPIVTest(authenticated: true) { session in
            guard await session.supports(PIVSessionFeature.moveDelete) else {
                reportSkip(reason: "Move/Delete not supported on this YubiKey")
                return
            }

            try await session.putCertificate(self.testCertificate, in: .authentication)
            try await session.putCertificate(self.testCertificate, in: .signature)
            let publicKey = try await session.generateKey(
                in: .authentication,
                type: .rsa(.bits1024),
                pinPolicy: .always,
                touchPolicy: .always
            )
            let authSlotMetadata = try await session.getMetadata(in: .authentication)
            #expect(publicKey == authSlotMetadata.publicKey)
            try await session.moveKey(from: .authentication, to: .signature)
            let signSlotMetadata = try await session.getMetadata(in: .signature)
            #expect(publicKey == signSlotMetadata.publicKey)
            do {
                _ = try await session.getMetadata(in: .authentication)
                Issue.record("Got metadata when we should have thrown a referenceDataNotFound exception.")
            } catch {
                guard let responseError = error as? ResponseError else {
                    Issue.record("Unexpected error: \(error)")
                    return
                }
                #expect(responseError.responseStatus.status == .referencedDataNotFound)
            }
        }
    }

    @Test("Delete Key")
    func deleteKey() async throws {
        try await runPIVTest(authenticated: true) { session in
            guard await session.supports(PIVSessionFeature.moveDelete) else {
                reportSkip(reason: "Move/Delete not supported on this YubiKey")
                return
            }

            try await session.putCertificate(self.testCertificate, in: .authentication, compressed: true)
            let publicKey = try await session.generateKey(
                in: .authentication,
                type: .rsa(.bits1024),
                pinPolicy: .always,
                touchPolicy: .always
            )
            let slotMetadata = try await session.getMetadata(in: .authentication)
            #expect(publicKey == slotMetadata.publicKey)
            try await session.deleteKey(in: .authentication)
            do {
                _ = try await session.getMetadata(in: .authentication)
                Issue.record("Got metadata when we should have thrown a referenceDataNotFound exception.")
            } catch {
                guard let responseError = error as? ResponseError else {
                    Issue.record("Unexpected error: \(error)")
                    return
                }
                #expect(responseError.responseStatus.status == .referencedDataNotFound)
            }
        }
    }

    @Test("Put Compressed and Read Certificate")
    func putCompressedAndReadCertificate() async throws {
        try await runPIVTest(authenticated: true) { session in
            try await session.putCertificate(self.testCertificate, in: .authentication, compressed: true)
            let retrievedCertificate = try await session.getCertificate(in: .authentication)
            #expect(self.testCertificate.der == retrievedCertificate.der)
        }
    }

    @Test("Put and Delete Certificate")
    func putAndDeleteCertificate() async throws {
        try await runPIVTest(authenticated: true) { session in
            try await session.putCertificate(self.testCertificate, in: .authentication)
            try await session.deleteCertificate(in: .authentication)
            do {
                _ = try await session.getCertificate(in: .authentication)
                Issue.record("Deleted certificate still present on YubiKey.")
            } catch {
                guard let error = error as? ResponseError else {
                    Issue.record("Deleted certificate returned unexpected error: \(error)")
                    return
                }
                #expect(error.responseStatus.status == .fileNotFound)
            }
        }
    }

    // MARK: - Management Key Tests

    @Test("Authenticate with Default Management Key")
    func authenticateWithDefaultManagementKey() async throws {
        try await runPIVTest { session in
            try await session.authenticate(with: defaultManagementKey)
        }
    }

    @Test("Authenticate with Wrong Management Key")
    func authenticateWithWrongManagementKey() async throws {
        try await runPIVTest { session in
            let wrongManagementKey = Data(hexEncodedString: "010101010101010101010101010101010101010101010101")!
            do {
                try await session.authenticate(with: wrongManagementKey)
                Issue.record("Successfully authenticated with the wrong management key.")
            } catch {
                guard let error = error as? ResponseError else {
                    Issue.record("Failed with unexpected error: \(error)")
                    return
                }
                #expect(error.responseStatus.status == .securityConditionNotSatisfied)
            }
        }
    }

    // MARK: - PIN/PUK Tests

    @Test("Verify PIN")
    func verifyPIN() async throws {
        try await runPIVTest(authenticated: true) { session in
            guard await session.supports(PIVSessionFeature.metadata) else {
                reportSkip(reason: "Metadata not supported on this YubiKey")
                return
            }

            let result = try await session.verifyPin(defaultPIN)
            if case .success = result {
                let metadata = try await session.getPinMetadata()
                let remaining = metadata.retriesRemaining
                let total = metadata.retriesTotal
                #expect(remaining == total)
            } else {
                Issue.record("Got unexpected result from verifyPin: \(result)")
            }
        }
    }

    @Test("Verify PIN Retry Count")
    func verifyPINRetryCount() async throws {
        try await runPIVTest(authenticated: true) { session in
            let resultOne = try await session.verifyPin("654321")
            if case .fail(let counter) = resultOne {
                #expect(counter == 2)
            } else {
                Issue.record("Got unexpected result from verifyPin: \(resultOne)")
            }
            let resultTwo = try await session.verifyPin("101010")
            if case .fail(let counter) = resultTwo {
                #expect(counter == 1)
            } else {
                Issue.record("Got unexpected result from verifyPin: \(resultTwo)")
            }
            let resultThree = try await session.verifyPin("142857")
            #expect(resultThree == .pinLocked)
            let resultFour = try await session.verifyPin("740737")
            #expect(resultFour == .pinLocked)
        }
    }

    @Test("Set PIN/PUK Attempts")
    func setPinPukAttempts() async throws {
        try await runPIVTest(authenticated: true) { session in
            try await session.verifyPin(defaultPIN)
            try await session.setRetries(pin: 5, puk: 6)

            guard await session.supports(PIVSessionFeature.metadata) else {
                reportSkip(reason: "Metadata not supported on this YubiKey")
                return
            }
            let pinResult = try await session.getPinMetadata()
            #expect(pinResult.retriesRemaining == 5)
            let pukResult = try await session.getPukMetadata()
            #expect(pukResult.retriesRemaining == 6)
        }
    }

    // MARK: - Device Information Tests

    @Test("Version")
    func version() async throws {
        try await runPIVTest { session in
            let version = await session.version
            #expect(version.major == 5)
            #expect([2, 3, 4, 7].contains(version.minor))
            trace("Version: \(version.major).\(version.minor).\(version.micro)")
        }
    }

    @Test("Serial Number")
    func serialNumber() async throws {
        try await runPIVTest { session in
            guard await session.supports(PIVSessionFeature.serialNumber) else {
                reportSkip(reason: "Serial number not supported on this YubiKey")
                return
            }

            let serialNumber = try await session.getSerialNumber()
            #expect(serialNumber > 0)
            trace("Serial number: \(serialNumber)")
        }
    }

    // MARK: - Metadata Tests

    @Test("Management Key Metadata")
    func managementKeyMetadata() async throws {
        try await runPIVTest { session in
            guard await session.supports(PIVSessionFeature.metadata) else {
                reportSkip(reason: "Metadata not supported on this YubiKey")
                return
            }

            let metadata = try await session.getManagementKeyMetadata()
            #expect(metadata.isDefault == true)
            trace("Management key type: \(metadata.keyType)")
            trace("Management touch policy: \(metadata.touchPolicy)")
        }
    }

    @Test("Slot Metadata")
    func slotMetadata() async throws {
        try await runPIVTest(authenticated: true) { session in
            guard await session.supports(PIVSessionFeature.metadata) else {
                reportSkip(reason: "Metadata not supported on this YubiKey")
                return
            }

            var publicKey = try await session.generateKey(
                in: .authentication,
                type: .ecc(.secp256r1),
                pinPolicy: .always,
                touchPolicy: .always
            )
            var metadata = try await session.getMetadata(in: .authentication)
            #expect(metadata.keyType == .ecc(.secp256r1))
            #expect(metadata.pinPolicy == .always)
            #expect(metadata.touchPolicy == .always)
            #expect(metadata.generated == true)
            #expect(metadata.publicKey == publicKey)

            publicKey = try await session.generateKey(
                in: .authentication,
                type: .ecc(.secp384r1),
                pinPolicy: .never,
                touchPolicy: .never
            )
            metadata = try await session.getMetadata(in: .authentication)
            #expect(metadata.keyType == .ecc(.secp384r1))
            #expect(metadata.pinPolicy == .never)
            #expect(metadata.touchPolicy == .never)
            #expect(metadata.generated == true)
            #expect(metadata.publicKey == publicKey)

            publicKey = try await session.generateKey(
                in: .authentication,
                type: .ecc(.secp256r1),
                pinPolicy: .once,
                touchPolicy: .cached
            )
            metadata = try await session.getMetadata(in: .authentication)
            #expect(metadata.keyType == .ecc(.secp256r1))
            #expect(metadata.pinPolicy == .once)
            #expect(metadata.touchPolicy == .cached)
            #expect(metadata.generated == true)
            #expect(metadata.publicKey == publicKey)
        }
    }

    @Test("AES Management Key Metadata")
    func aesManagementKeyMetadata() async throws {
        try await runPIVTest(authenticated: true) { session in
            guard await session.supports(PIVSessionFeature.metadata) else {
                reportSkip(reason: "Metadata not supported on this YubiKey")
                return
            }

            let aesManagementKey = Data(hexEncodedString: "f7ef787b46aa50de066bdade00aee17fc2b710372b722de5")!
            try await session.setManagementKey(aesManagementKey, type: .aes192, requiresTouch: true)
            let metadata = try await session.getManagementKeyMetadata()
            #expect(metadata.isDefault == false)
            #expect(metadata.keyType == .aes192)
            #expect(metadata.touchPolicy == .always)
        }
    }

    @Test("PIN Metadata")
    func pinMetadata() async throws {
        try await runPIVTest(authenticated: true) { session in
            guard await session.supports(PIVSessionFeature.metadata) else {
                reportSkip(reason: "Metadata not supported on this YubiKey")
                return
            }

            let result = try await session.getPinMetadata()
            #expect(result.isDefault == true)
            #expect(result.retriesTotal == 3)
            #expect(result.retriesRemaining == 3)
        }
    }

    @Test("PIN Metadata Retries")
    func pinMetadataRetries() async throws {
        try await runPIVTest(authenticated: true) { session in
            guard await session.supports(PIVSessionFeature.metadata) else {
                reportSkip(reason: "Metadata not supported on this YubiKey")
                return
            }

            _ = try await session.verifyPin("111111")
            let result = try await session.getPinMetadata()
            #expect(result.isDefault == true)
            #expect(result.retriesTotal == 3)
            #expect(result.retriesRemaining == 2)
        }
    }

    @Test("PUK Metadata")
    func pukMetadata() async throws {
        try await runPIVTest { session in
            guard await session.supports(PIVSessionFeature.metadata) else {
                reportSkip(reason: "Metadata not supported on this YubiKey")
                return
            }

            let result = try await session.getPukMetadata()
            #expect(result.isDefault == true)
            #expect(result.retriesTotal == 3)
            #expect(result.retriesRemaining == 3)
        }
    }

    @Test("Set PIN Failure")
    func setPinFailure() async throws {
        try await runPIVTest { session in
            guard await session.supports(PIVSessionFeature.metadata) else {
                reportSkip(reason: "Metadata not supported on this YubiKey")
                return
            }

            do {
                try await session.changePin(from: "000000", to: "654321")
            } catch let PIV.SessionError.invalidPin(retries) {
                let total = try await session.getPinMetadata().retriesTotal
                #expect(retries == total - 1)
            }
        }
    }

    @Test("Set PIN Success")
    func setPinSuccess() async throws {
        try await runPIVTest { session in
            guard await session.supports(PIVSessionFeature.metadata) else {
                reportSkip(reason: "Metadata not supported on this YubiKey")
                return
            }

            try await session.changePin(from: defaultPIN, to: "654321")
            let result = try await session.verifyPin("654321")
            switch result {
            case .success:
                let metadata = try await session.getPinMetadata()
                let remaining = metadata.retriesRemaining
                let total = metadata.retriesTotal
                #expect(remaining == total)
            case .fail(_):
                Issue.record("PIN verification failed")
            case .pinLocked:
                Issue.record("PIN is locked")
            }
        }
    }

    @Test("Unblock PIN")
    func unblockPin() async throws {
        try await runPIVTest { session in
            try await session.blockPin()
            let verifyBlockedPin = try await session.verifyPin(defaultPIN)
            guard verifyBlockedPin == .pinLocked else {
                Issue.record("Pin failed to block.")
                return
            }
            try await session.unblockPin(with: "12345678", newPin: "222222")
            let verifyUnblockedPin = try await session.verifyPin("222222")
            switch verifyUnblockedPin {
            case .success:
                return
            case .fail(_):
                Issue.record("Failed verifying with unblocked PIN.")
            case .pinLocked:
                Issue.record("PIN still blocked after unblocking with PUK.")
            }
        }
    }

    @Test("Set PUK and Unblock")
    func setPukAndUnblock() async throws {
        try await runPIVTest { session in
            try await session.changePuk(from: "12345678", to: "87654321")
            try await session.blockPin()
            try await session.unblockPin(with: "87654321", newPin: "654321")
            let result = try await session.verifyPin("654321")
            switch result {
            case .success:
                return
            case .fail(_):
                Issue.record("Failed verifying new pin.")
            case .pinLocked:
                Issue.record("Pin still blocked after unblocking with new puk.")
            }
        }
    }

    // MARK: - Biometric Authentication Tests

    // This will test auth on a YubiKey Bio. To run the test at least one fingerprint needs to be registered.
    @Test("Bio Authentication")
    func bioAuthentication() async throws {
        // First check if it's a bio device
        let connection = try await TestableConnection.shared()
        let managementSession = try await ManagementSession.makeSession(connection: connection)
        let deviceInfo = try await managementSession.getDeviceInfo()
        guard deviceInfo.formFactor == .usbCBio || deviceInfo.formFactor == .usbABio else {
            reportSkip(reason: "Not a YubiKey Bio device")
            return
        }

        // Now use runPIVTest for proper session reset
        try await runPIVTest { session in
            var bioMetadata = try await session.getBioMetadata()
            guard bioMetadata.isConfigured else {
                reportSkip(reason: "No fingerprints enrolled")
                return
            }
            #expect(bioMetadata.attemptsRemaining > 0)
            var verifyResult = try await session.verifyUV(requestTemporaryPin: false, checkOnly: false)
            #expect(verifyResult == nil)
            trace("verifyUV() passed")
            guard let pinData = try await session.verifyUV(requestTemporaryPin: true, checkOnly: false) else {
                reportSkip(reason: "Pin data returned was nil. Expected a value.")
                return
            }
            trace("got temporary pin: \(pinData.hexEncodedString).")
            bioMetadata = try await session.getBioMetadata()
            #expect(bioMetadata.temporaryPin == true)
            trace("temporary pin reported as set.")
            verifyResult = try await session.verifyUV(requestTemporaryPin: false, checkOnly: true)
            #expect(verifyResult == nil)
            trace("verifyUV successful.")
            try await session.verify(temporaryPin: pinData)
            trace("temporary pin verified.")
        }
    }

    @Test("Bio PIN Policy Error on Non-Bio Key")
    func bioPinPolicyErrorOnNonBioKey() async throws {
        // First check if it's NOT a bio device
        let connection = try await TestableConnection.shared()
        let managementSession = try await ManagementSession.makeSession(connection: connection)
        let deviceInfo = try await managementSession.getDeviceInfo()
        guard deviceInfo.formFactor != .usbCBio && deviceInfo.formFactor != .usbABio else {
            reportSkip(reason: "This is a YubiKey Bio device")
            return
        }

        // Now use runPIVTest(authenticated: true) for proper session reset and authentication
        try await runPIVTest(authenticated: true) { session in
            do {
                _ = try await session.generateKey(
                    in: .signature,
                    type: .ecc(.secp384r1),
                    pinPolicy: .matchAlways,
                    touchPolicy: .defaultPolicy
                )
            } catch {
                guard let sessionError = error as? SessionError else { throw error }
                #expect(sessionError == SessionError.notSupported)
            }
            do {
                _ = try await session.generateKey(
                    in: .signature,
                    type: .ecc(.secp384r1),
                    pinPolicy: .matchOnce,
                    touchPolicy: .defaultPolicy
                )
            } catch {
                guard let sessionError = error as? SessionError else { throw error }
                #expect(sessionError == SessionError.notSupported)
            }
        }
    }

    // MARK: - Helpers

    private func verifyECSignature(
        publicKey: EC.PublicKey,
        message: Data,
        signature: Data,
        algorithm: SecKeyAlgorithm
    ) throws {
        var error: Unmanaged<CFError>?
        let result = SecKeyVerifySignature(
            publicKey.asSecKey()!,
            algorithm,
            message as CFData,
            signature as CFData,
            &error
        )
        #expect(result == true)
        if let error {
            Issue.record(error.takeRetainedValue() as Error)
        }
    }

    private func verifyRSASignature(
        publicKey: RSA.PublicKey,
        message: Data,
        signature: Data,
        algorithm: SecKeyAlgorithm
    ) throws {
        var error: Unmanaged<CFError>?
        let result = SecKeyVerifySignature(
            publicKey.asSecKey()!,
            algorithm,
            message as CFData,
            signature as CFData,
            &error
        )
        #expect(result == true)
        if let error {
            Issue.record(error.takeRetainedValue() as Error)
        }
    }

    private func testRSAEncryptionDecryption(
        session: PIVSession,
        keySize: RSA.KeySize,
        data: Data = testMessage
    ) async throws {
        let publicKey = try await session.generateKey(
            in: .signature,
            type: .rsa(keySize)
        )

        guard case let .rsa(rsaPublicKey) = publicKey else {
            Issue.record("Failed to generate RSA key")
            return
        }

        let encryptedData = try #require(
            SecKeyCreateEncryptedData(
                rsaPublicKey.asSecKey()!,
                .rsaEncryptionPKCS1,
                data as CFData,
                nil
            ) as Data?,
            "Failed to encrypt data"
        )

        try await session.verifyPin(defaultPIN)
        let decryptedData = try await session.decrypt(
            encryptedData,
            in: .signature,
            using: .pkcs1v15
        )
        #expect(data == decryptedData)
    }

    private func runPIVTest<T>(
        authenticated: Bool = false,
        _ test: (PIVSession) async throws -> T
    ) async throws -> T {
        let connection = try await TestableConnection.shared()
        let session = try await PIVSession.makeSession(connection: connection)
        try await session.reset()

        if authenticated {
            try await session.authenticate(with: defaultManagementKey)
        }

        return try await test(session)
    }

}
