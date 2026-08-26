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
import Security
import YubiKit

/// PIV application scenarios.
public enum PIVScenario: CaseIterable {

    case eccp256Message
    case eccp256Digest
    case rsa1024Signatures
    case rsa2048Signatures
    case ed25519Signatures
    case rsa1024Decryption
    case rsa2048Decryption
    case ecdhP256
    case ecdhP384
    case x25519KeyAgreement
    case rsa1024KeyImport
    case rsa2048KeyImport
    case rsa3072KeyImport
    case rsa4096KeyImport
    case eccp256KeyImport
    case eccp384KeyImport
    case ed25519KeyImport
    case x25519KeyImport
    case rsa1024KeyGeneration
    case rsa2048KeyGeneration
    case rsa3072KeyGeneration
    case rsa4096KeyGeneration
    case eccp256KeyGeneration
    case eccp384KeyGeneration
    case ed25519KeyGeneration
    case x25519KeyGeneration
    case rsa
    case ed25519Attestation
    case x25519Attestation
    case putGet
    case putCompressedGet
    case putDelete
    case getWithoutAuth
    case move
    case delete
    case authenticateDefault
    case authenticateWrong
    case changeAndReauthenticate
    case verify
    case verifyRetryCount
    case setAttempts
    case changePinFailure
    case changePinSuccess
    case unblock
    case changePukUnblock
    case unblockWrongPuk
    case pinPolicyAlways
    case version
    case serialNumber
    case managementKey
    case slot
    case aesManagementKey
    case pin
    case pinRetries
    case puk
    case authentication
    case pinPolicyErrorNonBio
    case verifyUvWithoutFingerprints

    public var scenario: Scenario { definition }

    private var definition: Scenario {
        switch self {
        // MARK: - Certificate Signatures
        case .eccp256Message:
            return Scenario(
                "PIV.Signatures.eccp256Message",
                "signs a message with an ECC P-256 key (ECDSA SHA-256)",
                requirements: Requirements(capabilities: [.piv])
            ) { context in
                let session = try await context.pivSession(authenticated: true)
                let publicKey = try await session.generateKey(in: .signature, type: .ec(.secp256r1))
                guard case let .ec(ecPublicKey) = publicKey else {
                    context.record("Failed to generate EC key")
                    return
                }
                try await session.verifyPin(defaultPIN)
                let signature = try await session.sign(
                    testMessage,
                    in: .signature,
                    keyType: .ec(.secp256r1),
                    using: .hash(.sha256)
                )
                verifySignature(
                    context,
                    key: ecPublicKey.asSecKey(),
                    message: testMessage,
                    signature: signature,
                    algorithm: .ecdsaSignatureMessageX962SHA256
                )
            }
        case .eccp256Digest:
            return Scenario(
                "PIV.Signatures.eccp256Digest",
                "signs a pre-hashed digest with an ECC P-256 key",
                requirements: Requirements(capabilities: [.piv])
            ) { context in
                let session = try await context.pivSession(authenticated: true)
                let publicKey = try await session.generateKey(in: .signature, type: .ec(.secp256r1))
                guard case let .ec(ecPublicKey) = publicKey else {
                    context.record("Failed to generate EC key")
                    return
                }
                try await session.verifyPin(defaultPIN)
                let digestData = Data(SHA256.hash(data: testMessage))
                let signature = try await session.sign(
                    digestData,
                    in: .signature,
                    keyType: .ec(.secp256r1),
                    using: .prehashed(.sha256)
                )
                verifySignature(
                    context,
                    key: ecPublicKey.asSecKey(),
                    message: digestData,
                    signature: signature,
                    algorithm: .ecdsaSignatureDigestX962SHA256
                )
            }
        case .rsa1024Signatures: return rsaSignScenario(.bits1024, "PIV.Signatures.rsa1024")
        case .rsa2048Signatures: return rsaSignScenario(.bits2048, "PIV.Signatures.rsa2048")
        case .ed25519Signatures:
            return Scenario(
                "PIV.Signatures.ed25519",
                "signs a message with an Ed25519 key",
                requirements: Requirements(capabilities: [.piv], minVersion: Version("5.7.0"))
            ) { context in
                let session = try await context.pivSession(authenticated: true)
                let publicKey = try await session.generateKey(in: .signature, type: .ed25519)
                guard case let .ed25519(ed25519PublicKey) = publicKey else {
                    context.record("Failed to generate Ed25519 key")
                    return
                }
                try await session.verifyPin(defaultPIN)
                let signature = try await session.sign(testMessage, in: .signature, keyType: .ed25519)
                let cryptoKitPublicKey = try Curve25519.Signing.PublicKey(rawRepresentation: ed25519PublicKey.keyData)
                context.expect(
                    cryptoKitPublicKey.isValidSignature(signature, for: testMessage),
                    "Ed25519 signature must verify"
                )
            }
        // MARK: - Decrypt
        case .rsa1024Decryption: return rsaDecryptScenario(.bits1024, "PIV.Decryption.rsa1024")
        case .rsa2048Decryption: return rsaDecryptScenario(.bits2048, "PIV.Decryption.rsa2048")
        // MARK: - Key Agreement
        case .ecdhP256: return ecdhScenario(.secp256r1, "PIV.KeyAgreement.ecdhP256", curveName: "P-256")
        case .ecdhP384: return ecdhScenario(.secp384r1, "PIV.KeyAgreement.ecdhP384", curveName: "P-384")
        case .x25519KeyAgreement:
            return Scenario(
                "PIV.KeyAgreement.x25519",
                "computes an X25519 shared secret matching software ECDH",
                requirements: Requirements(capabilities: [.piv], minVersion: Version("5.7.0"))
            ) { context in
                let session = try await context.pivSession(authenticated: true)
                let publicKey = try await session.generateKey(in: .signature, type: .x25519)
                guard case let .x25519(yubiKeyPublicKey) = publicKey else {
                    context.record("Failed to generate X25519 key")
                    return
                }

                let cryptoKitPrivateKey = Curve25519.KeyAgreement.PrivateKey()
                let publicKeyData = cryptoKitPrivateKey.publicKey.rawRepresentation
                let yubiKitPublicKey = try context.require(
                    X25519.PublicKey(keyData: publicKeyData),
                    "Failed to create YubiKit X25519 public key"
                )

                try await session.verifyPin(defaultPIN)
                let yubiKeySecret = try await session.deriveSharedSecret(in: .signature, with: yubiKitPublicKey)

                let softwareSecret = try cryptoKitPrivateKey.sharedSecretFromKeyAgreement(
                    with: Curve25519.KeyAgreement.PublicKey(rawRepresentation: yubiKeyPublicKey.keyData)
                )
                let softwareSecretData = softwareSecret.withUnsafeBytes { Data($0) }
                context.expectEqual(softwareSecretData, yubiKeySecret, "X25519 shared secrets must match")
            }
        // MARK: - Key Import
        case .rsa1024KeyImport:
            return rsaImportScenario(
                .bits1024,
                "PIV.KeyImport.rsa1024",
                requirements: Requirements(capabilities: [.piv])
            )
        case .rsa2048KeyImport:
            return rsaImportScenario(
                .bits2048,
                "PIV.KeyImport.rsa2048",
                requirements: Requirements(capabilities: [.piv])
            )
        case .rsa3072KeyImport:
            return rsaImportScenario(
                .bits3072,
                "PIV.KeyImport.rsa3072",
                requirements: Requirements(capabilities: [.piv], minVersion: Version("5.7.0"))
            )
        case .rsa4096KeyImport:
            return rsaImportScenario(
                .bits4096,
                "PIV.KeyImport.rsa4096",
                requirements: Requirements(capabilities: [.piv], minVersion: Version("5.7.0"))
            )
        case .eccp256KeyImport: return ecImportScenario(.secp256r1, "PIV.KeyImport.eccp256")
        case .eccp384KeyImport: return ecImportScenario(.secp384r1, "PIV.KeyImport.eccp384")
        case .ed25519KeyImport:
            return Scenario(
                "PIV.KeyImport.ed25519",
                "imports an Ed25519 key and signs with it",
                requirements: Requirements(capabilities: [.piv], minVersion: Version("5.7.0"))
            ) { context in
                let session = try await context.pivSession(authenticated: true)
                let cryptoKitPrivateKey = Curve25519.Signing.PrivateKey()
                let cryptoKitPublicKey = cryptoKitPrivateKey.publicKey

                let yubiKitPublicKey = try context.require(
                    Ed25519.PublicKey(keyData: cryptoKitPublicKey.rawRepresentation),
                    "Failed to create YubiKit Ed25519 public key"
                )
                let yubiKitPrivateKey = try context.require(
                    Ed25519.PrivateKey(seed: cryptoKitPrivateKey.rawRepresentation, publicKey: yubiKitPublicKey),
                    "Failed to create YubiKit Ed25519 private key"
                )

                let keyType = try await session.putPrivateKey(
                    yubiKitPrivateKey,
                    in: .signature,
                    pinPolicy: .always,
                    touchPolicy: .never
                )
                context.expectEqual(keyType, PIV.Ed25519Key.ed25519, "stored key type should be Ed25519")

                try await session.verifyPin(defaultPIN)
                let signature = try await session.sign(testMessage, in: .signature, keyType: .ed25519)
                context.expect(
                    cryptoKitPublicKey.isValidSignature(signature, for: testMessage),
                    "imported Ed25519 key signature must verify"
                )
            }
        case .x25519KeyImport:
            return Scenario(
                "PIV.KeyImport.x25519",
                "imports an X25519 key and performs key agreement",
                requirements: Requirements(capabilities: [.piv], minVersion: Version("5.7.0"))
            ) { context in
                let session = try await context.pivSession(authenticated: true)
                let cryptoKitPrivateKey = Curve25519.KeyAgreement.PrivateKey()
                let cryptoKitPublicKey = cryptoKitPrivateKey.publicKey

                let yubiKitPublicKey = try context.require(
                    X25519.PublicKey(keyData: cryptoKitPublicKey.rawRepresentation),
                    "Failed to create YubiKit X25519 public key"
                )
                let yubiKitPrivateKey = try context.require(
                    X25519.PrivateKey(scalar: cryptoKitPrivateKey.rawRepresentation, publicKey: yubiKitPublicKey),
                    "Failed to create YubiKit X25519 private key"
                )

                let keyType = try await session.putPrivateKey(
                    yubiKitPrivateKey,
                    in: .signature,
                    pinPolicy: .always,
                    touchPolicy: .never
                )
                context.expectEqual(keyType, PIV.X25519Key.x25519, "stored key type should be X25519")

                let otherCryptoKitPrivateKey = Curve25519.KeyAgreement.PrivateKey()
                let otherCryptoKitPublicKey = otherCryptoKitPrivateKey.publicKey
                let otherYubiKitPublicKey = try context.require(
                    X25519.PublicKey(keyData: otherCryptoKitPublicKey.rawRepresentation),
                    "Failed to create other YubiKit X25519 public key"
                )

                try await session.verifyPin(defaultPIN)
                let yubiKeySecret = try await session.deriveSharedSecret(in: .signature, with: otherYubiKitPublicKey)

                let softwareSecret = try cryptoKitPrivateKey.sharedSecretFromKeyAgreement(with: otherCryptoKitPublicKey)
                let softwareSecretData = softwareSecret.withUnsafeBytes { Data($0) }
                context.expectEqual(softwareSecretData, yubiKeySecret, "imported X25519 key agreement must match")
            }
        // MARK: - Key Generation
        case .rsa1024KeyGeneration:
            return rsaGenerateScenario(
                .bits1024,
                "PIV.KeyGeneration.rsa1024",
                requirements: Requirements(capabilities: [.piv])
            )
        case .rsa2048KeyGeneration:
            return rsaGenerateScenario(
                .bits2048,
                "PIV.KeyGeneration.rsa2048",
                requirements: Requirements(capabilities: [.piv])
            )
        case .rsa3072KeyGeneration:
            return rsaGenerateScenario(
                .bits3072,
                "PIV.KeyGeneration.rsa3072",
                requirements: Requirements(capabilities: [.piv], minVersion: Version("5.7.0"))
            )
        case .rsa4096KeyGeneration:
            return rsaGenerateScenario(
                .bits4096,
                "PIV.KeyGeneration.rsa4096",
                requirements: Requirements(capabilities: [.piv], minVersion: Version("5.7.0"))
            )
        case .eccp256KeyGeneration: return ecGenerateScenario(.secp256r1, "PIV.KeyGeneration.eccp256")
        case .eccp384KeyGeneration: return ecGenerateScenario(.secp384r1, "PIV.KeyGeneration.eccp384")
        case .ed25519KeyGeneration:
            return Scenario(
                "PIV.KeyGeneration.ed25519",
                "generates an Ed25519 key",
                requirements: Requirements(capabilities: [.piv], minVersion: Version("5.7.0"))
            ) { context in
                let session = try await context.pivSession(authenticated: true)
                let result = try await session.generateKey(
                    in: .signature,
                    type: .ed25519,
                    pinPolicy: .always,
                    touchPolicy: .cached
                )
                guard case let .ed25519(publicKey) = result else {
                    context.record("Expected Ed25519 public key")
                    return
                }
                context.expectEqual(publicKey.keyData.count, 32, "Ed25519 public key should be 32 bytes")
            }
        case .x25519KeyGeneration:
            return Scenario(
                "PIV.KeyGeneration.x25519",
                "generates an X25519 key",
                requirements: Requirements(capabilities: [.piv], minVersion: Version("5.7.0"))
            ) { context in
                let session = try await context.pivSession(authenticated: true)
                let result = try await session.generateKey(
                    in: .signature,
                    type: .x25519,
                    pinPolicy: .always,
                    touchPolicy: .cached
                )
                guard case let .x25519(publicKey) = result else {
                    context.record("Expected X25519 public key")
                    return
                }
                context.expectEqual(publicKey.keyData.count, 32, "X25519 public key should be 32 bytes")
            }
        // MARK: - Attestation
        case .rsa:
            return Scenario(
                "PIV.Attestation.rsa",
                "attests a generated RSA key",
                requirements: Requirements(capabilities: [.piv], requiresRealHardware: true)
            ) { context in
                let session = try await context.pivSession(authenticated: true)
                let result = try await session.generateKey(in: .signature, type: .rsa(.bits1024))
                guard case let .rsa(publicKey) = result else {
                    context.record("Expected RSA public key")
                    return
                }
                let cert = try await session.attestKey(in: .signature)
                guard case let .rsa(attestKey) = cert.publicKey else {
                    context.record("Expected RSA public key in certificate")
                    return
                }
                context.expectEqual(attestKey, publicKey, "attested key must match the generated key")
            }
        case .ed25519Attestation:
            return Scenario(
                "PIV.Attestation.ed25519",
                "attests a generated Ed25519 key",
                requirements: Requirements(
                    capabilities: [.piv],
                    minVersion: Version("5.7.0"),
                    requiresRealHardware: true
                )
            ) { context in
                let session = try await context.pivSession(authenticated: true)
                let result = try await session.generateKey(in: .signature, type: .ed25519)
                guard case let .ed25519(publicKey) = result else {
                    context.record("Expected Ed25519 public key")
                    return
                }
                let cert = try await session.attestKey(in: .signature)
                guard case let .ed25519(attestKey) = cert.publicKey else {
                    context.record("Expected Ed25519 public key in certificate")
                    return
                }
                context.expectEqual(attestKey, publicKey, "attested key must match the generated key")
            }
        case .x25519Attestation:
            return Scenario(
                "PIV.Attestation.x25519",
                "attests a generated X25519 key",
                requirements: Requirements(
                    capabilities: [.piv],
                    minVersion: Version("5.7.0"),
                    requiresRealHardware: true
                )
            ) { context in
                let session = try await context.pivSession(authenticated: true)
                let result = try await session.generateKey(in: .signature, type: .x25519)
                guard case let .x25519(publicKey) = result else {
                    context.record("Expected X25519 public key")
                    return
                }
                let cert = try await session.attestKey(in: .signature)
                // X509Cert can't extract X25519 keys (SecTrustCopyKey yields no key for a
                // key-agreement-only SPKI), so settle for asserting the certificate exists.
                if case let .x25519(attestKey) = cert.publicKey {
                    context.expectEqual(attestKey, publicKey, "attested key must match the generated key")
                } else {
                    context.expect(cert.der.count > 0, "attestation certificate should be generated")
                }
            }
        // MARK: - Certificate Management
        case .putGet:
            return Scenario(
                "PIV.Certificates.putGet",
                "writes and reads back an X.509 certificate",
                requirements: Requirements(capabilities: [.piv])
            ) { context in
                let session = try await context.pivSession(authenticated: true)
                try await session.putCertificate(testCertificate, in: .authentication, compressed: false)
                let retrieved = try await session.getCertificate(in: .authentication)
                context.expectEqual(testCertificate.der, retrieved.der, "certificate should round-trip")
            }
        case .putCompressedGet:
            return Scenario(
                "PIV.Certificates.putCompressedGet",
                "writes a compressed certificate and reads it back decompressed",
                requirements: Requirements(capabilities: [.piv])
            ) { context in
                let session = try await context.pivSession(authenticated: true)
                try await session.putCertificate(testCertificate, in: .authentication, compressed: true)
                let retrieved = try await session.getCertificate(in: .authentication)
                context.expectEqual(testCertificate.der, retrieved.der, "compressed certificate should round-trip")
            }
        case .putDelete:
            return Scenario(
                "PIV.Certificates.putDelete",
                "deletes a stored certificate",
                requirements: Requirements(capabilities: [.piv])
            ) { context in
                let session = try await context.pivSession(authenticated: true)
                try await session.putCertificate(testCertificate, in: .authentication)
                try await session.deleteCertificate(in: .authentication)
                do {
                    _ = try await session.getCertificate(in: .authentication)
                    context.record("deleted certificate is still readable")
                } catch PIVSessionError.failedResponse(let response, _) {
                    context.expect(response.status == .fileNotFound, "expected fileNotFound after delete")
                }
            }
        case .getWithoutAuth:
            return Scenario(
                "PIV.Certificates.getWithoutAuth",
                "reads a stored certificate from a fresh, unauthenticated session",
                requirements: Requirements(capabilities: [.piv])
            ) { context in
                // Writing a certificate needs management-key auth; reading it back does not.
                let authenticated = try await context.pivSession(authenticated: true)
                try await authenticated.putCertificate(testCertificate, in: .authentication)

                // A fresh SELECT (no reset, so the certificate persists) is unauthenticated.
                let unauthenticated = try await context.pivSession(reset: false)
                let retrieved = try await unauthenticated.getCertificate(in: .authentication)
                context.expectEqual(
                    retrieved.der,
                    testCertificate.der,
                    "certificate should be readable without authentication"
                )
            }
        // MARK: - Move and Delete
        case .move:
            return Scenario(
                "PIV.KeyManagement.move",
                "moves a key from one slot to another",
                requirements: Requirements(capabilities: [.piv], minVersion: Version("5.7.0"))
            ) { context in
                let session = try await context.pivSession(authenticated: true)
                try await session.putCertificate(testCertificate, in: .authentication)
                try await session.putCertificate(testCertificate, in: .signature)
                let publicKey = try await session.generateKey(
                    in: .authentication,
                    type: .rsa(.bits1024),
                    pinPolicy: .always,
                    touchPolicy: .always
                )
                let authSlotMetadata = try await session.getMetadata(in: .authentication)
                context.expectEqual(publicKey, authSlotMetadata.publicKey, "source slot holds the generated key")

                try await session.moveKey(from: .authentication, to: .signature)
                let signSlotMetadata = try await session.getMetadata(in: .signature)
                context.expectEqual(publicKey, signSlotMetadata.publicKey, "destination slot holds the moved key")

                do {
                    _ = try await session.getMetadata(in: .authentication)
                    context.record("expected referencedDataNotFound after move, got metadata")
                } catch PIVSessionError.failedResponse(let response, _) {
                    context.expect(response.status == .referencedDataNotFound, "source slot should be empty after move")
                }
            }
        case .delete:
            return Scenario(
                "PIV.KeyManagement.delete",
                "deletes a key from a slot",
                requirements: Requirements(capabilities: [.piv], minVersion: Version("5.7.0"))
            ) { context in
                let session = try await context.pivSession(authenticated: true)
                try await session.putCertificate(testCertificate, in: .authentication, compressed: true)
                let publicKey = try await session.generateKey(
                    in: .authentication,
                    type: .rsa(.bits1024),
                    pinPolicy: .always,
                    touchPolicy: .always
                )
                let slotMetadata = try await session.getMetadata(in: .authentication)
                context.expectEqual(publicKey, slotMetadata.publicKey, "slot holds the generated key")

                try await session.deleteKey(in: .authentication)
                do {
                    _ = try await session.getMetadata(in: .authentication)
                    context.record("expected referencedDataNotFound after delete, got metadata")
                } catch PIVSessionError.failedResponse(let response, _) {
                    context.expect(response.status == .referencedDataNotFound, "slot should be empty after delete")
                }
            }
        // MARK: - Management Key
        case .authenticateDefault:
            return Scenario(
                "PIV.ManagementKey.authenticateDefault",
                "authenticates with the default management key",
                requirements: Requirements(capabilities: [.piv])
            ) { context in
                let session = try await context.pivSession()
                try await session.authenticate(with: Scenario.Context.defaultManagementKey)
            }
        case .authenticateWrong:
            return Scenario(
                "PIV.ManagementKey.authenticateWrong",
                "rejects a wrong management key",
                requirements: Requirements(capabilities: [.piv])
            ) { context in
                let session = try await context.pivSession()
                let wrongManagementKey = Data(hexString: "010101010101010101010101010101010101010101010101")!
                do {
                    try await session.authenticate(with: wrongManagementKey)
                    context.record("wrong management key should not authenticate")
                } catch PIVSessionError.failedResponse(let response, _) {
                    context.expect(
                        response.status == .securityConditionNotSatisfied,
                        "expected securityConditionNotSatisfied for a wrong management key"
                    )
                }
            }
        case .changeAndReauthenticate:
            return Scenario(
                "PIV.ManagementKey.changeAndReauthenticate",
                "a changed management key authenticates and the old key no longer does",
                requirements: Requirements(capabilities: [.piv], minVersion: Version("5.4.0"))
            ) { context in
                let session = try await context.pivSession(authenticated: true)
                let newKey = Data(hexString: "f7ef787b46aa50de066bdade00aee17fc2b710372b722de5")!
                try await session.setManagementKey(newKey, type: .aes192, requiresTouch: false)

                // A fresh SELECT on the same connection (no reset) is unauthenticated, and the change
                // persists across it: the old default key must no longer authenticate.
                let withOldKey = try await context.pivSession(reset: false)
                do {
                    try await withOldKey.authenticate(with: Scenario.Context.defaultManagementKey)
                    context.record("the old management key should no longer authenticate")
                } catch PIVSessionError.failedResponse(let response, _) {
                    context.expect(
                        response.status == .securityConditionNotSatisfied,
                        "expected securityConditionNotSatisfied for the old management key"
                    )
                }

                // The new key authenticates on a fresh SELECT.
                let withNewKey = try await context.pivSession(reset: false)
                try await withNewKey.authenticate(with: newKey)
            }
        // MARK: - PIN / PUK
        case .verify:
            return Scenario(
                "PIV.PinPuk.verify",
                "verifies the default PIN and resets the retry counter",
                requirements: Requirements(capabilities: [.piv], minVersion: Version("5.3.0"))
            ) { context in
                let session = try await context.pivSession(authenticated: true)
                let result = try await session.verifyPin(defaultPIN)
                if case .success = result {
                    let metadata = try await session.getPinMetadata()
                    context.expectEqual(
                        metadata.retriesRemaining,
                        metadata.retriesTotal,
                        "retries should be full after a successful verification"
                    )
                } else {
                    context.record("Got unexpected result from verifyPin: \(result)")
                }
            }
        case .verifyRetryCount:
            return Scenario(
                "PIV.PinPuk.verifyRetryCount",
                "decrements and then locks the PIN retry counter",
                requirements: Requirements(capabilities: [.piv], excludesBio: true)
            ) { context in
                let session = try await context.pivSession(authenticated: true)
                // Drive the loop off the device's retry count: each wrong PIN decrements it; the
                // attempt that exhausts it locks the PIN.
                let total = try await session.getPinMetadata().retriesTotal
                try context.require(total > 0, "PIN retry count should be positive, got \(total)")
                for attempt in 1...total {
                    let result = try await session.verifyPin("000000")
                    let remaining = total - attempt
                    if remaining > 0 {
                        context.expectEqual(
                            result,
                            .fail(remaining),
                            "\(remaining) retries should remain after \(attempt) wrong attempts"
                        )
                    } else {
                        context.expectEqual(result, .pinLocked, "PIN should be locked after \(total) wrong attempts")
                    }
                }
                context.expectEqual(try await session.verifyPin("740737"), .pinLocked, "PIN should remain locked")
            }
        case .setAttempts:
            return Scenario(
                "PIV.PinPuk.setAttempts",
                "sets the PIN and PUK retry attempts",
                requirements: Requirements(capabilities: [.piv], minVersion: Version("5.3.0"), excludesBio: true)
            ) { context in
                let session = try await context.pivSession(authenticated: true)
                try await session.verifyPin(defaultPIN)
                try await session.setRetries(pin: 5, puk: 6)

                let pinResult = try await session.getPinMetadata()
                context.expectEqual(pinResult.retriesRemaining, 5, "PIN attempts should be 5")
                let pukResult = try await session.getPukMetadata()
                context.expectEqual(pukResult.retriesRemaining, 6, "PUK attempts should be 6")
            }
        case .changePinFailure:
            return Scenario(
                "PIV.PinPuk.changePinFailure",
                "reports remaining retries when changing the PIN with a wrong old PIN",
                requirements: Requirements(capabilities: [.piv], minVersion: Version("5.3.0"))
            ) { context in
                let session = try await context.pivSession()
                do {
                    try await session.changePin(from: "000000", to: "654321")
                    context.record("changing the PIN with a wrong old PIN should have failed")
                } catch let PIVSessionError.invalidPin(retries, _) {
                    let total = try await session.getPinMetadata().retriesTotal
                    context.expectEqual(retries, total - 1, "one retry should have been consumed")
                }
            }
        case .changePinSuccess:
            return Scenario(
                "PIV.PinPuk.changePinSuccess",
                "changes the PIN and verifies with the new value",
                requirements: Requirements(capabilities: [.piv], minVersion: Version("5.3.0"))
            ) { context in
                let session = try await context.pivSession()
                // New PIN must satisfy YubiKey 5.7 PIN complexity (no monotonic run like "654321").
                try await session.changePin(from: defaultPIN, to: "284631")
                let result = try await session.verifyPin("284631")
                switch result {
                case .success:
                    let metadata = try await session.getPinMetadata()
                    context.expectEqual(
                        metadata.retriesRemaining,
                        metadata.retriesTotal,
                        "retries should be full after a successful verification"
                    )
                case .fail:
                    context.record("PIN verification failed")
                case .pinLocked:
                    context.record("PIN is locked")
                }
            }
        case .unblock:
            return Scenario(
                "PIV.PinPuk.unblock",
                "unblocks a blocked PIN with the PUK",
                requirements: Requirements(capabilities: [.piv], excludesBio: true)
            ) { context in
                let session = try await context.pivSession()
                try await session.blockPin()
                let verifyBlockedPin = try await session.verifyPin(defaultPIN)
                guard verifyBlockedPin == .pinLocked else {
                    context.record("PIN failed to block")
                    return
                }
                // New PIN must satisfy YubiKey 5.7 complexity (no all-identical "222222").
                try await session.unblockPin(with: defaultPUK, newPin: "273946")
                let verifyUnblockedPin = try await session.verifyPin("273946")
                switch verifyUnblockedPin {
                case .success:
                    return
                case .fail:
                    context.record("Failed to verify with the unblocked PIN")
                case .pinLocked:
                    context.record("PIN still blocked after unblocking with the PUK")
                }
            }
        case .changePukUnblock:
            return Scenario(
                "PIV.PinPuk.changePukUnblock",
                "changes the PUK and uses it to unblock the PIN",
                requirements: Requirements(capabilities: [.piv], excludesBio: true)
            ) { context in
                let session = try await context.pivSession()
                // New PUK/PIN must satisfy YubiKey 5.7 complexity (no monotonic run like "87654321").
                try await session.changePuk(from: defaultPUK, to: "28463175")
                try await session.blockPin()
                try await session.unblockPin(with: "28463175", newPin: "284631")
                let result = try await session.verifyPin("284631")
                switch result {
                case .success:
                    return
                case .fail:
                    context.record("Failed to verify the new PIN")
                case .pinLocked:
                    context.record("PIN still blocked after unblocking with the new PUK")
                }
            }
        case .unblockWrongPuk:
            return Scenario(
                "PIV.PinPuk.unblockWrongPuk",
                "unblocking the PIN with a wrong PUK reports invalidPin with one retry consumed",
                requirements: Requirements(capabilities: [.piv], minVersion: Version("5.3.0"), excludesBio: true)
            ) { context in
                let session = try await context.pivSession()
                let total = try await session.getPukMetadata().retriesTotal
                do {
                    try await session.unblockPin(with: "00000000", newPin: "273946")
                    context.record("unblocking with a wrong PUK should have failed")
                } catch let PIVSessionError.invalidPin(retries, _) {
                    context.expectEqual(retries, total - 1, "one PUK retry should have been consumed")
                }
            }
        // MARK: - Operations (PIN policy)
        case .pinPolicyAlways:
            return Scenario(
                "PIV.Operations.pinPolicyAlways",
                "a key with PIN policy ALWAYS requires a fresh PIN verification before every signature",
                requirements: Requirements(capabilities: [.piv])
            ) { context in
                let session = try await context.pivSession(authenticated: true)
                // touchPolicy .never keeps the flow PIN-only; pinPolicy .always demands a fresh verify per sign.
                _ = try await session.generateKey(
                    in: .authentication,
                    type: .ec(.secp256r1),
                    pinPolicy: .always,
                    touchPolicy: .never
                )

                // Without a PIN verification, signing must be rejected.
                do {
                    _ = try await session.sign(
                        testMessage,
                        in: .authentication,
                        keyType: .ec(.secp256r1),
                        using: .hash(.sha256)
                    )
                    context.record("signing without a PIN should have failed under PIN policy ALWAYS")
                } catch PIVSessionError.failedResponse(let response, _) {
                    context.expect(
                        response.status == .securityConditionNotSatisfied,
                        "expected securityConditionNotSatisfied when signing without a PIN"
                    )
                }

                // A fresh PIN verification permits exactly one signature.
                try await session.verifyPin(defaultPIN)
                let firstSignature = try await session.sign(
                    testMessage,
                    in: .authentication,
                    keyType: .ec(.secp256r1),
                    using: .hash(.sha256)
                )
                context.expect(!firstSignature.isEmpty, "the first signature after verifying the PIN should succeed")

                // ALWAYS consumes the verification, so the next signature is rejected again.
                do {
                    _ = try await session.sign(
                        testMessage,
                        in: .authentication,
                        keyType: .ec(.secp256r1),
                        using: .hash(.sha256)
                    )
                    context.record("a second signature without re-verifying the PIN should have failed")
                } catch PIVSessionError.failedResponse(let response, _) {
                    context.expect(
                        response.status == .securityConditionNotSatisfied,
                        "expected securityConditionNotSatisfied for a second signature without a fresh PIN"
                    )
                }

                // Re-verifying restores the ability to sign.
                try await session.verifyPin(defaultPIN)
                let secondSignature = try await session.sign(
                    testMessage,
                    in: .authentication,
                    keyType: .ec(.secp256r1),
                    using: .hash(.sha256)
                )
                context.expect(!secondSignature.isEmpty, "signing after re-verifying the PIN should succeed")
            }
        // MARK: - Device Information
        case .version:
            return Scenario(
                "PIV.DeviceInfo.version",
                "reports a firmware version",
                requirements: Requirements(capabilities: [.piv])
            ) { context in
                let session = try await context.pivSession()
                let version = await session.version
                context.expect(version.major == 5, "expected firmware v5, got \(version)")
                context.log("version: \(version.major).\(version.minor).\(version.micro)")
            }
        case .serialNumber:
            return Scenario(
                "PIV.DeviceInfo.serialNumber",
                "reports a serial number",
                requirements: Requirements(capabilities: [.piv], minVersion: Version("5.0.0"))
            ) { context in
                let session = try await context.pivSession()
                let serialNumber = try await session.getSerialNumber()
                context.expect(serialNumber > 0, "serial number should be greater than 0")
                context.log("serial number: \(serialNumber)")
            }
        // MARK: - Metadata
        case .managementKey:
            return Scenario(
                "PIV.Metadata.managementKey",
                "reads default management key metadata",
                requirements: Requirements(capabilities: [.piv], minVersion: Version("5.3.0"))
            ) { context in
                let session = try await context.pivSession()
                let metadata = try await session.getManagementKeyMetadata()
                context.expect(metadata.isDefault == true, "management key should be the default")
                context.log("management key type: \(metadata.keyType)")
                context.log("management touch policy: \(metadata.touchPolicy)")
            }
        case .slot:
            return Scenario(
                "PIV.Metadata.slot",
                "reads slot metadata for generated keys across PIN/touch policies",
                requirements: Requirements(capabilities: [.piv], minVersion: Version("5.3.0"))
            ) { context in
                let session = try await context.pivSession(authenticated: true)

                var publicKey = try await session.generateKey(
                    in: .authentication,
                    type: .ec(.secp256r1),
                    pinPolicy: .always,
                    touchPolicy: .always
                )
                var slotMetadata = try await session.getMetadata(in: .authentication)
                context.expectEqual(slotMetadata.keyType, .ec(.secp256r1), "key type")
                context.expectEqual(slotMetadata.pinPolicy, .always, "pin policy")
                context.expectEqual(slotMetadata.touchPolicy, .always, "touch policy")
                context.expect(slotMetadata.generated == true, "should be generated")
                context.expectEqual(slotMetadata.publicKey, publicKey, "public key")

                publicKey = try await session.generateKey(
                    in: .authentication,
                    type: .ec(.secp384r1),
                    pinPolicy: .never,
                    touchPolicy: .never
                )
                slotMetadata = try await session.getMetadata(in: .authentication)
                context.expectEqual(slotMetadata.keyType, .ec(.secp384r1), "key type")
                context.expectEqual(slotMetadata.pinPolicy, .never, "pin policy")
                context.expectEqual(slotMetadata.touchPolicy, .never, "touch policy")
                context.expect(slotMetadata.generated == true, "should be generated")
                context.expectEqual(slotMetadata.publicKey, publicKey, "public key")

                publicKey = try await session.generateKey(
                    in: .authentication,
                    type: .ec(.secp256r1),
                    pinPolicy: .once,
                    touchPolicy: .cached
                )
                slotMetadata = try await session.getMetadata(in: .authentication)
                context.expectEqual(slotMetadata.keyType, .ec(.secp256r1), "key type")
                context.expectEqual(slotMetadata.pinPolicy, .once, "pin policy")
                context.expectEqual(slotMetadata.touchPolicy, .cached, "touch policy")
                context.expect(slotMetadata.generated == true, "should be generated")
                context.expectEqual(slotMetadata.publicKey, publicKey, "public key")
            }
        case .aesManagementKey:
            return Scenario(
                "PIV.Metadata.aesManagementKey",
                "reads metadata after setting an AES-192 management key",
                requirements: Requirements(capabilities: [.piv], minVersion: Version("5.4.0"))
            ) { context in
                let session = try await context.pivSession(authenticated: true)
                let aesManagementKey = Data(hexString: "f7ef787b46aa50de066bdade00aee17fc2b710372b722de5")!
                try await session.setManagementKey(aesManagementKey, type: .aes192, requiresTouch: true)
                let metadata = try await session.getManagementKeyMetadata()
                context.expect(metadata.isDefault == false, "management key should no longer be default")
                context.expectEqual(metadata.keyType, .aes192, "management key type should be AES-192")
                context.expectEqual(metadata.touchPolicy, .always, "touch policy should be always")
            }
        case .pin:
            return Scenario(
                "PIV.Metadata.pin",
                "reads default PIN metadata",
                requirements: Requirements(capabilities: [.piv], minVersion: Version("5.3.0"))
            ) { context in
                let session = try await context.pivSession(authenticated: true)
                let result = try await session.getPinMetadata()
                context.expect(result.isDefault == true, "PIN should be the default")
                // An untouched PIN reports full retries; the default count is SKU-dependent (3 on a 5, 8 on Bio).
                context.expectEqual(result.retriesRemaining, result.retriesTotal, "remaining retries should be full")
            }
        case .pinRetries:
            return Scenario(
                "PIV.Metadata.pinRetries",
                "reflects a consumed retry in PIN metadata",
                requirements: Requirements(capabilities: [.piv], minVersion: Version("5.3.0"))
            ) { context in
                let session = try await context.pivSession(authenticated: true)
                _ = try await session.verifyPin("111111")
                let result = try await session.getPinMetadata()
                context.expect(result.isDefault == true, "PIN should still be the default")
                // One failed verification consumes exactly one retry (the total is SKU-dependent: 3 on a 5, 8 on Bio).
                context.expectEqual(result.retriesRemaining, result.retriesTotal - 1, "remaining after one failure")
            }
        case .puk:
            return Scenario(
                "PIV.Metadata.puk",
                "reads default PUK metadata",
                requirements: Requirements(capabilities: [.piv], minVersion: Version("5.3.0"), excludesBio: true)
            ) { context in
                let session = try await context.pivSession()
                let result = try await session.getPukMetadata()
                context.expect(result.isDefault == true, "PUK should be the default")
                context.expectEqual(result.retriesTotal, 3, "total retries")
                context.expectEqual(result.retriesRemaining, 3, "remaining retries")
            }
        // MARK: - Bio (multi-protocol)
        case .authentication:
            return Scenario(
                "PIV.Bio.authentication",
                "authenticates with biometrics and a temporary PIN (YubiKey Bio)",
                requirements: Requirements(capabilities: [.piv], requiresBio: true)
            ) { context in
                let session = try await context.pivSession()
                var bioMetadata = try await session.getBioMetadata()
                guard bioMetadata.isConfigured else {
                    try context.skip("no fingerprints enrolled on this YubiKey Bio")
                }
                context.expect(bioMetadata.attemptsRemaining > 0, "bio attempts should remain")

                context.touch("Touch the fingerprint sensor to verify your identity")
                var verifyResult = try await session.verifyUV(requestTemporaryPin: false, checkOnly: false)
                context.expect(verifyResult == nil, "verifyUV without a temporary PIN should return nil")

                guard let pinData = try await session.verifyUV(requestTemporaryPin: true, checkOnly: false) else {
                    context.record("expected a temporary PIN, got nil")
                    return
                }
                context.log("got temporary PIN: \(pinData.hexString)")

                bioMetadata = try await session.getBioMetadata()
                context.expect(bioMetadata.temporaryPin == true, "temporary PIN should be reported as set")

                verifyResult = try await session.verifyUV(requestTemporaryPin: false, checkOnly: true)
                context.expect(verifyResult == nil, "verifyUV check-only should return nil")

                try await session.verify(temporaryPin: pinData)
            }
        case .pinPolicyErrorNonBio:
            return Scenario(
                "PIV.Bio.pinPolicyErrorNonBio",
                "rejects match PIN policies on a non-Bio YubiKey",
                requirements: Requirements(capabilities: [.piv], excludesBio: true)
            ) { context in
                let session = try await context.pivSession(authenticated: true)
                do {
                    _ = try await session.generateKey(
                        in: .signature,
                        type: .ec(.secp384r1),
                        pinPolicy: .matchAlways,
                        touchPolicy: .defaultPolicy
                    )
                    context.record("Expected error for matchAlways on non-Bio YubiKey")
                } catch let PIVSessionError.failedResponse(response, source: _) {
                    context.expect(response.status == .referencedDataNotFound, "matchAlways should be rejected")
                }
                do {
                    _ = try await session.generateKey(
                        in: .signature,
                        type: .ec(.secp384r1),
                        pinPolicy: .matchOnce,
                        touchPolicy: .defaultPolicy
                    )
                    context.record("Expected error for matchOnce on non-Bio YubiKey")
                } catch let PIVSessionError.failedResponse(response, source: _) {
                    context.expect(response.status == .referencedDataNotFound, "matchOnce should be rejected")
                }
            }
        case .verifyUvWithoutFingerprints:
            return Scenario(
                "PIV.Bio.verifyUvWithoutFingerprints",
                "verifyUV is rejected on a Bio device with no fingerprints enrolled",
                requirements: Requirements(capabilities: [.piv], requiresBio: true)
            ) { context in
                let session = try await context.pivSession()
                let bioMetadata = try await session.getBioMetadata()
                guard !bioMetadata.isConfigured else {
                    try context.skip("fingerprints are enrolled; this scenario needs an unenrolled Bio device")
                }
                do {
                    _ = try await session.verifyUV(requestTemporaryPin: false, checkOnly: true)
                    context.record("verifyUV should fail without enrolled fingerprints")
                } catch PIVSessionError.invalidPin {
                    context.log("verifyUV correctly rejected with invalidPin")
                }
            }
        }
    }
}

// MARK: - Test data

private let defaultPIN = Scenario.Context.defaultPIVPin
private let defaultPUK = "12345678"
private let testMessage = Data("Hello world!".utf8)

private let testCertificate = X509Cert(
    der: Data(
        base64Encoded:
            "MIIBKzCB0qADAgECAhQTuU25u6oazORvKfTleabdQaDUGzAKBggqhkjOPQQDAjAWMRQwEgYDVQQDDAthbW9zLmJ1cnRvbjAeFw0yMTAzMTUxMzU5MjVaFw0yODA1MTcwMDAwMDBaMBYxFDASBgNVBAMMC2Ftb3MuYnVydG9uMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEofwN6S+atSZmzeLK7aSI+mJJwxh0oUBiCOngHLeToYeanrTGvCZQ2AK/R9esnqSxMyBUDp91UO4F6U4c6RTooTAKBggqhkjOPQQDAgNIADBFAiAnj/KUSpW7l5wnenQEbwWudK/7q3WtyrqdB0H1xc258wIhALDLImzu3S+0TT2/ggM95LLWE4Llfa2RQM71bnW6zqqn"
    )!
)

// MARK: - Parameterized scenario builders

private func rsaSignScenario(_ keySize: RSA.KeySize, _ id: String) -> Scenario {
    Scenario(
        id,
        "signs a message with an RSA-\(keySize.bitCount) key (PKCS#1 v1.5 SHA-512)",
        requirements: Requirements(capabilities: [.piv])
    ) { context in
        let session = try await context.pivSession(authenticated: true)
        let publicKey = try await session.generateKey(in: .signature, type: .rsa(keySize))
        guard case let .rsa(rsaPublicKey) = publicKey else {
            context.record("Failed to generate RSA key")
            return
        }
        try await session.verifyPin(defaultPIN)
        let signature = try await session.sign(
            testMessage,
            in: .signature,
            keyType: .rsa(keySize),
            using: .pkcs1v15(.sha512)
        )
        verifySignature(
            context,
            key: rsaPublicKey.asSecKey(),
            message: testMessage,
            signature: signature,
            algorithm: .rsaSignatureMessagePKCS1v15SHA512
        )
    }
}

private func rsaDecryptScenario(_ keySize: RSA.KeySize, _ id: String) -> Scenario {
    Scenario(
        id,
        "decrypts with a generated RSA-\(keySize.bitCount) key (PKCS#1 v1.5)",
        requirements: Requirements(capabilities: [.piv])
    ) { context in
        let session = try await context.pivSession(authenticated: true)
        let publicKey = try await session.generateKey(in: .signature, type: .rsa(keySize))
        guard case let .rsa(rsaPublicKey) = publicKey else {
            context.record("Failed to generate RSA key")
            return
        }
        let secKey = try context.require(rsaPublicKey.asSecKey(), "Failed to convert RSA public key to SecKey")
        let encryptedData = try context.require(
            SecKeyCreateEncryptedData(secKey, .rsaEncryptionPKCS1, testMessage as CFData, nil) as Data?,
            "Failed to encrypt data"
        )
        try await session.verifyPin(defaultPIN)
        let decryptedData = try await session.decrypt(encryptedData, in: .signature, using: .pkcs1v15)
        context.expectEqual(testMessage, decryptedData, "decrypted data should match the plaintext")
    }
}

private func ecdhScenario(_ curve: EC.Curve, _ id: String, curveName: String) -> Scenario {
    Scenario(
        id,
        "computes an ECDH shared secret with \(curveName) matching software ECDH",
        requirements: Requirements(capabilities: [.piv])
    ) { context in
        let session = try await context.pivSession(authenticated: true)
        let publicKey = try await session.generateKey(in: .signature, type: .ec(curve))
        guard case let .ec(yubiKeyPublicKey) = publicKey else {
            context.record("Failed to generate EC key")
            return
        }
        try await session.verifyPin(defaultPIN)

        let peerPublicKey: EC.PublicKey
        let softwareSecret: Data
        switch curve {
        case .secp256r1:
            let peer = P256.KeyAgreement.PrivateKey()
            peerPublicKey = try context.require(
                EC.PublicKey(x963: peer.publicKey.x963Representation, curve: curve),
                "Failed to build peer public key"
            )
            let yubiKitPublicKey = try P256.KeyAgreement.PublicKey(x963Representation: yubiKeyPublicKey.x963)
            softwareSecret = try peer.sharedSecretFromKeyAgreement(with: yubiKitPublicKey).withUnsafeBytes { Data($0) }
        case .secp384r1:
            let peer = P384.KeyAgreement.PrivateKey()
            peerPublicKey = try context.require(
                EC.PublicKey(x963: peer.publicKey.x963Representation, curve: curve),
                "Failed to build peer public key"
            )
            let yubiKitPublicKey = try P384.KeyAgreement.PublicKey(x963Representation: yubiKeyPublicKey.x963)
            softwareSecret = try peer.sharedSecretFromKeyAgreement(with: yubiKitPublicKey).withUnsafeBytes { Data($0) }
        }

        let yubiKeySecret = try await session.deriveSharedSecret(in: .signature, with: peerPublicKey)
        context.expectEqual(softwareSecret, yubiKeySecret, "ECDH shared secrets must match")
    }
}

private func rsaImportScenario(
    _ keySize: RSA.KeySize,
    _ id: String,
    requirements: Requirements
) -> Scenario {
    Scenario(
        id,
        "imports an RSA-\(keySize.bitCount) key and decrypts with it",
        requirements: requirements
    ) { context in
        let session = try await context.pivSession(authenticated: true)
        let privateKey = try context.require(
            randomRSAPrivateKey(keySize),
            "Failed to generate a software RSA-\(keySize.bitCount) key"
        )
        let publicKey = privateKey.publicKey

        let keyType = try await session.putPrivateKey(
            privateKey,
            in: .signature,
            pinPolicy: .always,
            touchPolicy: .never
        )
        context.expectEqual(keyType, PIV.RSAKey.rsa(keySize), "stored key type should be RSA-\(keySize.bitCount)")

        let secKey = try context.require(publicKey.asSecKey(), "Failed to convert RSA public key to SecKey")
        let encryptedData = try context.require(
            SecKeyCreateEncryptedData(secKey, .rsaEncryptionPKCS1, testMessage as CFData, nil) as Data?,
            "Failed to encrypt data with SecKeyCreateEncryptedData"
        )

        try await session.verifyPin(defaultPIN)
        let decryptedData = try await session.decrypt(encryptedData, in: .signature, using: .pkcs1v15)
        context.expectEqual(testMessage, decryptedData, "decrypted data should match the plaintext")
    }
}

private func ecImportScenario(_ curve: EC.Curve, _ id: String) -> Scenario {
    Scenario(
        id,
        "imports an EC \(curve == .secp256r1 ? "P-256" : "P-384") key and signs with it",
        requirements: Requirements(capabilities: [.piv])
    ) { context in
        let session = try await context.pivSession(authenticated: true)

        let privateKey: EC.PrivateKey
        switch curve {
        case .secp256r1:
            privateKey = try context.require(
                EC.PrivateKey(x963: P256.Signing.PrivateKey().x963Representation, curve: curve),
                "Failed to build EC private key"
            )
        case .secp384r1:
            privateKey = try context.require(
                EC.PrivateKey(x963: P384.Signing.PrivateKey().x963Representation, curve: curve),
                "Failed to build EC private key"
            )
        }
        let publicKey = privateKey.publicKey

        let keyType = try await session.putPrivateKey(
            privateKey,
            in: .signature,
            pinPolicy: .always,
            touchPolicy: .never
        )
        context.expectEqual(keyType, PIV.ECKey.ec(curve), "stored key type should match the imported curve")

        try await session.verifyPin(defaultPIN)
        let signature = try await session.sign(
            testMessage,
            in: .signature,
            keyType: .ec(curve),
            using: .hash(.sha256)
        )
        verifySignature(
            context,
            key: publicKey.asSecKey(),
            message: testMessage,
            signature: signature,
            algorithm: .ecdsaSignatureMessageX962SHA256
        )
    }
}

private func rsaGenerateScenario(
    _ keySize: RSA.KeySize,
    _ id: String,
    requirements: Requirements
) -> Scenario {
    Scenario(
        id,
        "generates an RSA-\(keySize.bitCount) key",
        requirements: requirements
    ) { context in
        let session = try await context.pivSession(authenticated: true)
        let result = try await session.generateKey(
            in: .signature,
            type: .rsa(keySize),
            pinPolicy: .always,
            touchPolicy: .cached
        )
        guard case let .rsa(publicKey) = result else {
            context.record("Expected RSA public key")
            return
        }
        context.expectEqual(publicKey.size, keySize, "generated key size should match")
    }
}

private func ecGenerateScenario(_ curve: EC.Curve, _ id: String) -> Scenario {
    Scenario(
        id,
        "generates an EC \(curve == .secp256r1 ? "P-256" : "P-384") key",
        requirements: Requirements(capabilities: [.piv])
    ) { context in
        let session = try await context.pivSession(authenticated: true)
        let result = try await session.generateKey(
            in: .signature,
            type: .ec(curve),
            pinPolicy: .always,
            touchPolicy: .cached
        )
        guard case let .ec(publicKey) = result else {
            context.record("Expected EC public key")
            return
        }
        context.expectEqual(publicKey.curve, curve, "generated curve should match")
    }
}

// MARK: - Verification helpers
//
// CryptoKit doesn't support RSA or verifying pre-hashed EC digests, so we go through `SecKey`.

private func verifySignature(
    _ context: Scenario.Context,
    key: SecKey?,
    message: Data,
    signature: Data,
    algorithm: SecKeyAlgorithm
) {
    guard let key else {
        context.record("Failed to convert public key to SecKey")
        return
    }
    var error: Unmanaged<CFError>?
    let result = SecKeyVerifySignature(key, algorithm, message as CFData, signature as CFData, &error)
    context.expect(result, "signature verification failed")
    if let error {
        context.record("\(error.takeRetainedValue() as Error)")
    }
}

/// Generates a software RSA private key and exports it as PKCS#1.
private func randomRSAPrivateKey(_ keySize: RSA.KeySize) -> RSA.PrivateKey? {
    let attributes: [CFString: Any] = [
        kSecAttrKeyType: kSecAttrKeyTypeRSA,
        kSecAttrKeySizeInBits: keySize.rawValue,
    ]
    var error: Unmanaged<CFError>?
    guard let secKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error),
        let der = SecKeyCopyExternalRepresentation(secKey, &error) as Data?
    else {
        return nil
    }
    return RSA.PrivateKey(pkcs1: der)
}

// MARK: - SecKey conversion

extension RSA.PublicKey {
    fileprivate func asSecKey() -> SecKey? {
        let attributes: [CFString: Any] = [
            kSecAttrKeyClass: kSecAttrKeyClassPublic,
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits: size.rawValue,
        ]
        return SecKeyCreateWithData(pkcs1 as CFData, attributes as CFDictionary, nil)
    }
}

extension EC.PublicKey {
    fileprivate func asSecKey() -> SecKey? {
        let attributes: [CFString: Any] = [
            kSecAttrKeyClass: kSecAttrKeyClassPublic,
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: curve.keySizeInBits,
        ]
        return SecKeyCreateWithData(x963 as CFData, attributes as CFDictionary, nil)
    }
}
