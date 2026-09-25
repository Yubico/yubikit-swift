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
enum PIVScenario: CaseIterable, ScenarioSuite {

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
    case importPinPolicyAlways
    case importTouchPolicyAlways
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
    case exportAttestationCertificate
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
    case pinPolicyOnce
    case pinPolicyNever
    case slotMetadataPut
    case setPinRetriesRoundTrip
    case version
    case managementKey
    case slot
    case aesManagementKey
    case pin
    case pinRetries
    case puk
    case authentication
    case pinPolicyErrorNonBio
    case verifyUvWithoutFingerprints
    case generateKeyRequiresAuth
    case putCertificateRequiresAuth
    case putKeyRequiresAuth

    var scenario: Scenario { definition }

    private var definition: Scenario {
        switch self {
        // MARK: - TestOperations
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
        // MARK: - TestDecrypt
        // See importDecryptScenarios for the import port.
        case .rsa1024Decryption: return rsaDecryptScenario(.bits1024, "PIV.Decryption.rsa1024")
        case .rsa2048Decryption: return rsaDecryptScenario(.bits2048, "PIV.Decryption.rsa2048")
        // MARK: - TestKeyAgreement
        case .ecdhP256: return ecdhScenario(.secp256r1, "PIV.KeyAgreement.ecdhP256", curveName: "P-256")
        case .ecdhP384: return ecdhScenario(.secp384r1, "PIV.KeyAgreement.ecdhP384", curveName: "P-384")
        case .x25519KeyAgreement:
            return Scenario(
                "PIV.KeyAgreement.x25519",
                "computes an X25519 shared secret matching software ECDH",
                // X25519 is outside the FIPS-approved set; a FIPS device rejects it at the wire.
                requirements: Requirements(capabilities: [.piv], minVersion: Version("5.7.0"), excludesFIPS: true)
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
        // MARK: - TestKeyManagement (put_key)
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
        // the CLI only imports the ECCP256 key, while this also signs with it to confirm the round-trip).
        case .eccp256KeyImport: return ecImportScenario(.secp256r1, "PIV.KeyImport.eccp256")
        case .eccp384KeyImport: return ecImportScenario(.secp384r1, "PIV.KeyImport.eccp384")
        // (import_key puts an Ed25519 key, then signs; Ed25519 ∈ SIGN_KEY_TYPES)
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
                // X25519 is outside the FIPS-approved set; a FIPS device rejects it at the wire.
                requirements: Requirements(capabilities: [.piv], minVersion: Version("5.7.0"), excludesFIPS: true)
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
        case .importPinPolicyAlways:
            return Scenario(
                "PIV.KeyImport.pinPolicyAlways",
                "imports an EC P-256 key with PIN policy ALWAYS and reads it back from metadata",
                requirements: Requirements(capabilities: [.piv], minVersion: Version("5.3.0"))
            ) { context in
                let session = try await context.pivSession(authenticated: true)
                let privateKey = try context.require(
                    EC.PrivateKey(x963: P256.Signing.PrivateKey().x963Representation, curve: .secp256r1),
                    "Failed to build EC private key"
                )
                try await session.putPrivateKey(
                    privateKey,
                    in: .authentication,
                    pinPolicy: .always,
                    touchPolicy: .defaultPolicy
                )
                let metadata = try await session.getMetadata(in: .authentication)
                context.expectEqual(metadata.pinPolicy, .always, "imported key should report PIN policy ALWAYS")
            }
        case .importTouchPolicyAlways:
            return Scenario(
                "PIV.KeyImport.touchPolicyAlways",
                "imports an EC P-256 key with touch policy ALWAYS and reads it back from metadata",
                requirements: Requirements(capabilities: [.piv], minVersion: Version("5.3.0"))
            ) { context in
                let session = try await context.pivSession(authenticated: true)
                let privateKey = try context.require(
                    EC.PrivateKey(x963: P256.Signing.PrivateKey().x963Representation, curve: .secp256r1),
                    "Failed to build EC private key"
                )
                try await session.putPrivateKey(
                    privateKey,
                    in: .authentication,
                    pinPolicy: .defaultPolicy,
                    touchPolicy: .always
                )
                let metadata = try await session.getMetadata(in: .authentication)
                context.expectEqual(metadata.touchPolicy, .always, "imported key should report touch policy ALWAYS")
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
                // X25519 is outside the FIPS-approved set; a FIPS device rejects it at the wire.
                requirements: Requirements(capabilities: [.piv], minVersion: Version("5.7.0"), excludesFIPS: true)
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
        // then attests; here an RSA key is generated and the attested public key is checked against it).
        case .rsa:
            return Scenario(
                "PIV.Attestation.rsa",
                "attests a generated RSA key",
                // Uses RSA-1024, which a FIPS device rejects; skip on FIPS hardware.
                requirements: Requirements(capabilities: [.piv], excludesFIPS: true, requiresRealHardware: true)
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
                // X25519 is outside the FIPS-approved set; skip on FIPS hardware.
                requirements: Requirements(
                    capabilities: [.piv],
                    minVersion: Version("5.7.0"),
                    excludesFIPS: true,
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
        case .exportAttestationCertificate:
            return Scenario(
                "PIV.Attestation.exportCertificate",
                "reads the static attestation certificate from slot f9",
                requirements: Requirements(capabilities: [.piv])
            ) { context in
                // Reading a stored certificate needs no management-key authentication.
                let session = try await context.pivSession(reset: false)
                do {
                    let cert = try await session.getCertificate(in: .attestation)
                    // A real attestation cert always carries a parsable public key (RSA/EC, Yubico-provisioned).
                    context.expect(cert.publicKey != nil, "attestation certificate should expose a public key")
                } catch PIVSessionError.failedResponse(let response, _) {
                    // The static attestation cert is Yubico-provisioned; a twin may not provision slot f9.
                    try context.skip("no attestation certificate in slot f9: \(response.status)")
                }
            }
        // MARK: - TestCompressedCertificate / TestKeyManagement (certificates)
        // (the CLI writes a cert into the AUTHENTICATION object and reads it back as DER; here the same
        // uncompressed put+get round-trip via putCertificate/getCertificate).
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
        // MARK: - TestMoveAndDelete
        case .move:
            return Scenario(
                "PIV.KeyManagement.move",
                "moves a key from one slot to another",
                requirements: Requirements(capabilities: [.piv], minVersion: Version("5.7.0"))
            ) { context in
                let session = try await context.pivSession(authenticated: true)
                try await session.putCertificate(testCertificate, in: .authentication)
                try await session.putCertificate(testCertificate, in: .signature)
                // EC P-256 (not RSA-1024) so this key-management test runs on FIPS too.
                let publicKey = try await session.generateKey(
                    in: .authentication,
                    type: .ec(.secp256r1),
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
                // EC P-256 (not RSA-1024) so this key-management test runs on FIPS too.
                let publicKey = try await session.generateKey(
                    in: .authentication,
                    type: .ec(.secp256r1),
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
        // MARK: - TestManagementKeyReadWrite
        // Authenticate with the default management key and verify it does not throw.
        case .authenticateDefault:
            return Scenario(
                "PIV.ManagementKey.authenticateDefault",
                "authenticates with the default management key",
                requirements: Requirements(capabilities: [.piv])
            ) { context in
                let session = try await context.pivSession()
                try await session.authenticate(with: Scenario.Context.defaultManagementKey)
            }
        // Authenticating with the wrong management key should raise an ApduError.
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
        // MARK: - TestUnblockPin / TestMetadata (PIN/PUK)
        // the retry counter resets; the metadata round-trip is its own TestMetadata::test_pin_metadata).
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
        // loops wrong-PIN attempts until "PIN tries remaining: 0"; here each wrong verifyPin is asserted to
        // decrement the counter and the final attempt locks the PIN).
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
        // (the metadata half: set retries, then read back the new PIN/PUK totals).
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
        // change-pin with a now-wrong old PIN raises SystemExit; here the wrong old PIN reports the
        // remaining retries, which the CLI does not assert).
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
        // change-pin to a non-default value succeeds; here the change is followed by a verify with the
        // new PIN, which the CLI does not do).
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
        // separately in TestPuk::test_change_puk and TestPuk::test_unblock_pin, but never changes the PUK
        // and then uses the new PUK to unblock the PIN in one flow).
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
        // MARK: - TestOperations (PIN policy)
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
        case .pinPolicyOnce:
            return Scenario(
                "PIV.Operations.pinPolicyOnce",
                "a key with PIN policy ONCE needs one verify per session, then re-verify after a fresh session",
                // The cross-session half (re-SELECT clears the PIN-ONCE verification) needs real silicon:
                // the twin can't both clear PIN state and keep the generated key, since a fresh twin
                // connection is factory-clean NVRAM.
                requirements: Requirements(
                    capabilities: [.piv],
                    minVersion: Version("4.0.0"),
                    requiresRealHardware: true
                )
            ) { context in
                let session = try await context.pivSession(authenticated: true)
                // touchPolicy .never keeps the flow PIN-only; pinPolicy .once demands a single verify per session.
                _ = try await session.generateKey(
                    in: .authentication,
                    type: .ec(.secp256r1),
                    pinPolicy: .once,
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
                    context.record("signing without a PIN should have failed under PIN policy ONCE")
                } catch PIVSessionError.failedResponse(let response, _) {
                    context.expect(
                        response.status == .securityConditionNotSatisfied,
                        "expected securityConditionNotSatisfied when signing without a PIN"
                    )
                }

                // One verify permits multiple signatures within the same session.
                try await session.verifyPin(defaultPIN)
                let firstSignature = try await session.sign(
                    testMessage,
                    in: .authentication,
                    keyType: .ec(.secp256r1),
                    using: .hash(.sha256)
                )
                context.expect(!firstSignature.isEmpty, "first signature after verifying the PIN should succeed")
                let secondSignature = try await session.sign(
                    testMessage,
                    in: .authentication,
                    keyType: .ec(.secp256r1),
                    using: .hash(.sha256)
                )
                context.expect(!secondSignature.isEmpty, "a second signature in the same session should succeed")

                // A fresh SELECT (no reset, so the key persists) clears the verification; the PIN is required again.
                let fresh = try await context.pivSession(reset: false)
                do {
                    _ = try await fresh.sign(
                        testMessage,
                        in: .authentication,
                        keyType: .ec(.secp256r1),
                        using: .hash(.sha256)
                    )
                    context.record("signing in a fresh session without re-verifying should have failed")
                } catch PIVSessionError.failedResponse(let response, _) {
                    context.expect(
                        response.status == .securityConditionNotSatisfied,
                        "expected securityConditionNotSatisfied in a fresh session before re-verifying"
                    )
                }

                // Re-verifying in the fresh session restores the ability to sign.
                try await fresh.verifyPin(defaultPIN)
                let thirdSignature = try await fresh.sign(
                    testMessage,
                    in: .authentication,
                    keyType: .ec(.secp256r1),
                    using: .hash(.sha256)
                )
                context.expect(!thirdSignature.isEmpty, "signing after re-verifying in a fresh session should succeed")
            }
        case .pinPolicyNever:
            return Scenario(
                "PIV.Operations.pinPolicyNever",
                "a key with PIN policy NEVER signs without any PIN verification",
                requirements: Requirements(capabilities: [.piv], minVersion: Version("4.0.0"), excludesFIPS: true)
            ) { context in
                let session = try await context.pivSession(authenticated: true)
                _ = try await session.generateKey(
                    in: .authentication,
                    type: .ec(.secp256r1),
                    pinPolicy: .never,
                    touchPolicy: .never
                )
                // No verifyPin: the NEVER policy lets the key sign straight away.
                let signature = try await session.sign(
                    testMessage,
                    in: .authentication,
                    keyType: .ec(.secp256r1),
                    using: .hash(.sha256)
                )
                context.expect(!signature.isEmpty, "signing under PIN policy NEVER should succeed without a PIN")
            }
        // MARK: - TestMetadata (slot put)
        case .slotMetadataPut:
            return Scenario(
                "PIV.Metadata.slotPut",
                "reads slot metadata for an imported (generated == false) key",
                requirements: Requirements(capabilities: [.piv], minVersion: Version("5.3.0"))
            ) { context in
                let session = try await context.pivSession(authenticated: true)

                // Import a software EC P-256 key, then assert the slot metadata reflects an imported key.
                let cryptoKitPrivateKey = P256.Signing.PrivateKey()
                let privateKey = try context.require(
                    EC.PrivateKey(x963: cryptoKitPrivateKey.x963Representation, curve: .secp256r1),
                    "Failed to build EC private key"
                )
                try await session.putPrivateKey(
                    privateKey,
                    in: .signature,
                    pinPolicy: .always,
                    touchPolicy: .never
                )

                let metadata = try await session.getMetadata(in: .signature)
                context.expectEqual(metadata.keyType, .ec(.secp256r1), "key type")
                context.expectEqual(metadata.pinPolicy, .always, "pin policy")
                context.expectEqual(metadata.touchPolicy, .never, "touch policy")
                context.expect(metadata.generated == false, "imported key should report generated == false")
                context.expectEqual(
                    metadata.publicKey,
                    .ec(privateKey.publicKey),
                    "metadata public key should match the imported key"
                )
            }
        // MARK: - TestUnblockPin (set pin retries)
        case .setPinRetriesRoundTrip:
            return Scenario(
                "PIV.PinPuk.setPinRetriesRoundTrip",
                "setRetries takes effect, and wrong PIN/PUK then report the new remaining counts",
                requirements: Requirements(capabilities: [.piv], minVersion: Version("5.3.0"), excludesBio: true)
            ) { context in
                let session = try await context.pivSession(authenticated: true)
                let pinTries: UInt8 = 9
                let pukTries: UInt8 = 7

                try await session.verifyPin(defaultPIN)
                try await session.setRetries(pin: pinTries, puk: pukTries)

                context.expectEqual(
                    try await session.getPinMetadata().retriesTotal,
                    Int(pinTries),
                    "PIN total retries should be the new value"
                )

                // A wrong PIN now reports pinTries - 1 remaining.
                let pinResult = try await session.verifyPin("000000")
                context.expectEqual(
                    pinResult,
                    .fail(Int(pinTries) - 1),
                    "a wrong PIN should leave pinTries - 1 attempts"
                )

                // A wrong PUK (via change-PUK) reports pukTries - 1 remaining.
                do {
                    try await session.changePuk(from: "00000000", to: defaultPUK)
                    context.record("changing the PUK with a wrong old PUK should have failed")
                } catch let PIVSessionError.invalidPin(retries, _) {
                    context.expectEqual(retries, Int(pukTries) - 1, "a wrong PUK should leave pukTries - 1 attempts")
                }
            }
        // MARK: - Device Information
        // `piv info`; here the firmware version is read and checked to be v5).
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
        // MARK: - TestMetadata
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
        // (generate per PIN/touch policy and assert key type, policies, generated flag, public key).
        case .slot:
            return Scenario(
                "PIV.Metadata.slot",
                "reads slot metadata for generated keys across PIN/touch policies",
                // Exercises PIN policy NEVER, which a FIPS device forbids; skip on FIPS.
                requirements: Requirements(capabilities: [.piv], minVersion: Version("5.3.0"), excludesFIPS: true)
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
        // failed verify to assert the consumed retry rather than reading the default-state metadata).
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
        // cli/piv reads PUK tries only as `piv info` text).
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
        // MARK: - TestBioMpe
        // fingerprints and cli/piv has no Bio coverage; the full biometric + temporary-PIN flow is not covered).
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
        // rejected on a non-Bio YubiKey).
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
        // MARK: - TestKeyManagement (generate requires auth)
        case .generateKeyRequiresAuth:
            return Scenario(
                "PIV.KeyManagement.generateKeyRequiresAuth",
                "generateKey without a prior management-key authenticate is rejected",
                // The twin does not gate generateKey on management-key auth (it succeeds there),
                // so this only meaningfully runs on real silicon.
                requirements: Requirements(capabilities: [.piv], requiresRealHardware: true)
            ) { context in
                // No authenticate(): a fresh, reset session has not unlocked the management key.
                let session = try await context.pivSession(authenticated: false, reset: true)
                do {
                    _ = try await session.generateKey(in: .authentication, type: .ec(.secp256r1))
                    context.record("generateKey without authentication should have failed")
                } catch PIVSessionError.failedResponse(let response, _) {
                    context.expect(
                        response.status == .securityConditionNotSatisfied,
                        "expected securityConditionNotSatisfied generating a key without auth, got \(response.status)"
                    )
                }
            }
        case .putCertificateRequiresAuth:
            return Scenario(
                "PIV.KeyManagement.putCertificateRequiresAuth",
                "putCertificate without a prior management-key authenticate is rejected",
                requirements: Requirements(capabilities: [.piv], requiresRealHardware: true)
            ) { context in
                let session = try await context.pivSession(authenticated: false, reset: true)
                do {
                    try await session.putCertificate(testCertificate, in: .authentication)
                    context.record("putCertificate without authentication should have failed")
                } catch PIVSessionError.failedResponse(let response, _) {
                    context.expect(
                        response.status == .securityConditionNotSatisfied,
                        "expected securityConditionNotSatisfied putting a certificate without auth, got \(response.status)"
                    )
                }
            }
        case .putKeyRequiresAuth:
            return Scenario(
                "PIV.KeyManagement.putKeyRequiresAuth",
                "putKey without a prior management-key authenticate is rejected",
                requirements: Requirements(capabilities: [.piv], requiresRealHardware: true)
            ) { context in
                let session = try await context.pivSession(authenticated: false, reset: true)
                let privateKey = try context.require(
                    EC.PrivateKey(x963: P256.Signing.PrivateKey().x963Representation, curve: .secp256r1),
                    "Failed to build EC private key"
                )
                do {
                    try await session.putPrivateKey(
                        privateKey,
                        in: .authentication,
                        pinPolicy: .defaultPolicy,
                        touchPolicy: .defaultPolicy
                    )
                    context.record("putPrivateKey without authentication should have failed")
                } catch PIVSessionError.failedResponse(let response, _) {
                    context.expect(
                        response.status == .securityConditionNotSatisfied,
                        "expected securityConditionNotSatisfied putting a key without auth, got \(response.status)"
                    )
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

/// Key types outside the FIPS-approved set (RSA-1024 and X25519). A YubiKey 5 FIPS rejects
/// generating or importing them at the wire with `incorrectParameters` (0x6A80).
private func fipsForbidden(_ keyType: PIV.KeyType) -> Bool {
    keyType == .rsa(.bits1024) || keyType == .x25519
}

private func rsaSignScenario(_ keySize: RSA.KeySize, _ id: String) -> Scenario {
    Scenario(
        id,
        "signs a message with an RSA-\(keySize.bitCount) key (PKCS#1 v1.5 SHA-512)",
        // RSA-1024 is below the FIPS-approved set; a FIPS device rejects it at the wire.
        requirements: Requirements(capabilities: [.piv], excludesFIPS: keySize == .bits1024)
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
        // RSA-1024 is below the FIPS-approved set; a FIPS device rejects it at the wire.
        requirements: Requirements(capabilities: [.piv], excludesFIPS: keySize == .bits1024)
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
    var requirements = requirements
    // RSA-1024 is below the FIPS-approved set; a FIPS device rejects it at the wire.
    if keySize == .bits1024 { requirements.excludesFIPS = true }
    return Scenario(
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
    var requirements = requirements
    // RSA-1024 is below the FIPS-approved set; a FIPS device rejects it at the wire.
    if keySize == .bits1024 { requirements.excludesFIPS = true }
    return Scenario(
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

// MARK: - Parameterized scenario families
//
// Parameterized families: import-decrypt, slot-metadata-generate, import-ECDH, FIPS key-type rejection,
// and weak-PIN rejection.

extension PIVScenario {

    static var parameterizedScenarios: [Scenario] {
        importDecryptScenarios + slotMetadataGenerateScenarios + importEcdhScenarios + fipsRejectionScenarios
            + weakPinRejectionScenarios
    }

    // MARK: - TestPinComplexity
    // complexity enabled, changing the PIN to a weak value (all-repeated digits, or a known-weak pattern)
    // is rejected with 0x6985 (conditions-not-satisfied). PIN complexity is a 5.7 feature; there is no
    // `requiresPinComplexity` requirement, so each scenario reads DeviceInfo at runtime and skips
    // when the device does not enforce complexity.
    private struct WeakPinParam: ScenarioParameter {
        let idSuffix: String
        let displayName: String
        let requirements: Requirements
        let weakPin: String

        init(_ idSuffix: String, _ weakPin: String) {
            self.idSuffix = idSuffix
            self.displayName = "PIN complexity rejects changing the PIN to the weak value \(idSuffix)"
            // PIN complexity is a YubiKey 5.7 feature; gate on the firmware as a floor, then
            // confirm complexity is actually enabled inside the body before asserting rejection.
            self.requirements = Requirements(capabilities: [.piv], minVersion: Version("5.7.0"))
            self.weakPin = weakPin
        }
    }

    private static var weakPinRejectionScenarios: [Scenario] {
        // Repeated-digit PINs of varied lengths plus a known-weak repeated pattern.
        let params: [WeakPinParam] = [
            WeakPinParam("111111", "111111"),
            WeakPinParam("22222222", "22222222"),
            WeakPinParam("333333", "333333"),
            WeakPinParam("123123", "123123"),
        ]
        return Scenario.parameterized("PIV.PinComplexity.rejectsWeakPins", over: params) { context, param in
            let info = try await context.provider.deviceInfo()
            guard info.pinComplexity else {
                try context.skip("device does not enforce PIN complexity")
            }
            let session = try await context.pivSession(authenticated: true)
            try await session.verifyPin(defaultPIN)
            do {
                try await session.changePin(from: defaultPIN, to: param.weakPin)
                context.record("weak PIN \(param.idSuffix) should have been rejected under PIN complexity")
            } catch PIVSessionError.failedResponse(let response, _) {
                context.expect(
                    response.status == .conditionsNotSatisfied,
                    "expected conditionsNotSatisfied (0x6985) rejecting weak PIN \(param.idSuffix), got \(response.status)"
                )
            }
        }
    }

    // MARK: - FIPS enforcement
    // condition/skip rather than asserting they are rejected; these mirror the `excludesFIPS` scenarios, run only on FIPS).
    private struct FIPSRejectionParam: ScenarioParameter {
        let idSuffix: String
        let displayName: String
        let requirements: Requirements
        let keyType: PIV.KeyType

        init(_ idSuffix: String, _ keyType: PIV.KeyType) {
            self.idSuffix = idSuffix
            self.displayName = "a FIPS device rejects generating a \(idSuffix) key (outside the approved set)"
            self.requirements = Requirements(capabilities: [.piv], minVersion: Version("5.7.0"), requiresFIPS: true)
            self.keyType = keyType
        }
    }

    private static var fipsRejectionScenarios: [Scenario] {
        let keyTypeRejections = Scenario.parameterized(
            "PIV.FIPS.rejectsForbiddenKeyType",
            over: [FIPSRejectionParam("rsa1024", .rsa(.bits1024)), FIPSRejectionParam("x25519", .x25519)]
        ) { context, param in
            let session = try await context.pivSession(authenticated: true)
            do {
                _ = try await session.generateKey(in: .signature, type: param.keyType)
                context.record("a FIPS device should reject generating a \(param.idSuffix) key")
            } catch PIVSessionError.failedResponse(let response, _) {
                context.expect(
                    response.status == .incorrectParameters,
                    "expected incorrectParameters (0x6A80) rejecting \(param.idSuffix), got \(response.status)"
                )
            }
        }

        let neverPolicyRejection = Scenario(
            "PIV.FIPS.rejectsPinPolicyNever",
            "a FIPS device rejects generating a key with PIN policy NEVER",
            requirements: Requirements(capabilities: [.piv], minVersion: Version("5.7.0"), requiresFIPS: true)
        ) { context in
            let session = try await context.pivSession(authenticated: true)
            do {
                _ = try await session.generateKey(
                    in: .signature,
                    type: .ec(.secp256r1),
                    pinPolicy: .never,
                    touchPolicy: .never
                )
                context.record("a FIPS device should reject a key with PIN policy NEVER")
            } catch PIVSessionError.failedResponse(let response, _) {
                context.expect(
                    response.status == .incorrectParameters,
                    "expected incorrectParameters (0x6A80) rejecting PIN policy NEVER, got \(response.status)"
                )
            }
        }

        return keyTypeRejections + [neverPolicyRejection]
    }

    // MARK: - TestDecrypt
    // a random plaintext in software (PKCS#1 v1.5), and verify the on-device decrypt round-trips.
    private struct ImportDecryptParam: ScenarioParameter {
        let idSuffix: String
        let displayName: String
        let requirements: Requirements
        let keySize: RSA.KeySize

        init(_ keySize: RSA.KeySize, minVersion: Version?) {
            self.idSuffix = "rsa\(keySize.bitCount)"
            self.displayName =
                "imports an RSA-\(keySize.bitCount) key into KEY_MANAGEMENT and decrypts a random plaintext"
            // RSA-1024 is below the FIPS-approved set; a FIPS device rejects it at the wire.
            self.requirements = Requirements(
                capabilities: [.piv],
                minVersion: minVersion,
                excludesFIPS: keySize == .bits1024
            )
            self.keySize = keySize
        }
    }

    private static var importDecryptScenarios: [Scenario] {
        let params: [ImportDecryptParam] = [
            ImportDecryptParam(.bits1024, minVersion: nil),
            ImportDecryptParam(.bits2048, minVersion: nil),
            ImportDecryptParam(.bits3072, minVersion: Version("5.7.0")),
            ImportDecryptParam(.bits4096, minVersion: Version("5.7.0")),
        ]
        return Scenario.parameterized("PIV.Decrypt.import", over: params) { context, param in
            let session = try await context.pivSession(authenticated: true)
            let privateKey = try context.require(
                randomRSAPrivateKey(param.keySize),
                "Failed to generate a software RSA-\(param.keySize.bitCount) key"
            )
            let publicKey = privateKey.publicKey

            let keyType = try await session.putPrivateKey(
                privateKey,
                in: .keyManagement,
                pinPolicy: .always,
                touchPolicy: .never
            )
            context.expectEqual(keyType, PIV.RSAKey.rsa(param.keySize), "stored key type")

            // Encrypt 32 random bytes in software with the public key (PKCS#1 v1.5), mirroring os.urandom(32).
            let plaintext = randomBytes(count: 32)
            let secKey = try context.require(publicKey.asSecKey(), "Failed to convert RSA public key to SecKey")
            let encryptedData = try context.require(
                SecKeyCreateEncryptedData(secKey, .rsaEncryptionPKCS1, plaintext as CFData, nil) as Data?,
                "Failed to encrypt plaintext with SecKeyCreateEncryptedData"
            )

            try await session.verifyPin(defaultPIN)
            let decryptedData = try await session.decrypt(encryptedData, in: .keyManagement, using: .pkcs1v15)
            context.expectEqual(plaintext, decryptedData, "decrypted data should match the random plaintext")
        }
    }

    // MARK: - TestMetadata (slot generate)
    // metadata (keyType, pinPolicy ALWAYS, touchPolicy NEVER, generated == true, public-key match).
    private struct SlotMetadataGenerateParam: ScenarioParameter {
        let idSuffix: String
        let displayName: String
        let requirements: Requirements
        let keyType: PIV.KeyType

        init(_ idSuffix: String, _ keyType: PIV.KeyType, minVersion: Version?) {
            self.idSuffix = idSuffix
            self.displayName = "reads slot metadata for a generated \(idSuffix) key"
            self.requirements = Requirements(
                capabilities: [.piv],
                minVersion: minVersion ?? Version("5.3.0"),
                excludesFIPS: fipsForbidden(keyType)
            )
            self.keyType = keyType
        }
    }

    private static var slotMetadataGenerateScenarios: [Scenario] {
        let v570 = Version("5.7.0")
        let params: [SlotMetadataGenerateParam] = [
            SlotMetadataGenerateParam("rsa1024", .rsa(.bits1024), minVersion: nil),
            SlotMetadataGenerateParam("rsa2048", .rsa(.bits2048), minVersion: nil),
            SlotMetadataGenerateParam("rsa3072", .rsa(.bits3072), minVersion: v570),
            SlotMetadataGenerateParam("rsa4096", .rsa(.bits4096), minVersion: v570),
            SlotMetadataGenerateParam("eccp256", .ec(.secp256r1), minVersion: nil),
            SlotMetadataGenerateParam("eccp384", .ec(.secp384r1), minVersion: nil),
            SlotMetadataGenerateParam("ed25519", .ed25519, minVersion: v570),
            SlotMetadataGenerateParam("x25519", .x25519, minVersion: v570),
        ]
        return Scenario.parameterized("PIV.Metadata.slotGenerate", over: params) { context, param in
            let session = try await context.pivSession(authenticated: true)
            // pin_policy DEFAULT resolves to ALWAYS and touch_policy to NEVER for the SIGNATURE slot.
            let publicKey = try await session.generateKey(
                in: .signature,
                type: param.keyType,
                pinPolicy: .always,
                touchPolicy: .never
            )
            let metadata = try await session.getMetadata(in: .signature)
            context.expectEqual(metadata.keyType, param.keyType, "key type")
            context.expectEqual(metadata.pinPolicy, .always, "pin policy")
            context.expectEqual(metadata.touchPolicy, .never, "touch policy")
            context.expect(metadata.generated == true, "generated key should report generated == true")
            context.expectEqual(metadata.publicKey, publicKey, "metadata public key should match the generated key")
        }
    }

    // MARK: - TestKeyAgreement (import)
    // on-device shared secret matches a software ECDH against a fresh peer key.
    private struct ImportEcdhParam: ScenarioParameter {
        let idSuffix: String
        let displayName: String
        let requirements: Requirements
        let keyType: PIV.KeyType

        init(_ idSuffix: String, _ keyType: PIV.KeyType, minVersion: Version?) {
            self.idSuffix = idSuffix
            self.displayName = "imports a \(idSuffix) key and computes a shared secret matching software ECDH"
            self.requirements = Requirements(
                capabilities: [.piv],
                minVersion: minVersion,
                excludesFIPS: fipsForbidden(keyType)
            )
            self.keyType = keyType
        }
    }

    private static var importEcdhScenarios: [Scenario] {
        let params: [ImportEcdhParam] = [
            ImportEcdhParam("eccp256", .ec(.secp256r1), minVersion: nil),
            ImportEcdhParam("eccp384", .ec(.secp384r1), minVersion: nil),
            ImportEcdhParam("x25519", .x25519, minVersion: Version("5.7.0")),
        ]
        return Scenario.parameterized("PIV.KeyAgreement.import", over: params) { context, param in
            let session = try await context.pivSession(authenticated: true)

            switch param.keyType {
            case .ec(let curve):
                let peerSecret: Data
                let peerPublicKey: EC.PublicKey
                let importedPrivateKey: EC.PrivateKey
                switch curve {
                case .secp256r1:
                    let deviceKey = P256.KeyAgreement.PrivateKey()
                    importedPrivateKey = try context.require(
                        EC.PrivateKey(x963: deviceKey.x963Representation, curve: curve),
                        "Failed to build EC private key"
                    )
                    let peer = P256.KeyAgreement.PrivateKey()
                    peerPublicKey = try context.require(
                        EC.PublicKey(x963: peer.publicKey.x963Representation, curve: curve),
                        "Failed to build peer public key"
                    )
                    let devicePublicKey = try P256.KeyAgreement.PublicKey(
                        x963Representation: importedPrivateKey.publicKey.x963
                    )
                    peerSecret = try peer.sharedSecretFromKeyAgreement(with: devicePublicKey)
                        .withUnsafeBytes { Data($0) }
                case .secp384r1:
                    let deviceKey = P384.KeyAgreement.PrivateKey()
                    importedPrivateKey = try context.require(
                        EC.PrivateKey(x963: deviceKey.x963Representation, curve: curve),
                        "Failed to build EC private key"
                    )
                    let peer = P384.KeyAgreement.PrivateKey()
                    peerPublicKey = try context.require(
                        EC.PublicKey(x963: peer.publicKey.x963Representation, curve: curve),
                        "Failed to build peer public key"
                    )
                    let devicePublicKey = try P384.KeyAgreement.PublicKey(
                        x963Representation: importedPrivateKey.publicKey.x963
                    )
                    peerSecret = try peer.sharedSecretFromKeyAgreement(with: devicePublicKey)
                        .withUnsafeBytes { Data($0) }
                }

                try await session.putPrivateKey(
                    importedPrivateKey,
                    in: .keyManagement,
                    pinPolicy: .always,
                    touchPolicy: .never
                )
                try await session.verifyPin(defaultPIN)
                let yubiKeySecret = try await session.deriveSharedSecret(in: .keyManagement, with: peerPublicKey)
                context.expectEqual(peerSecret, yubiKeySecret, "imported EC key agreement must match software ECDH")

            case .x25519:
                let deviceKey = Curve25519.KeyAgreement.PrivateKey()
                let importedPublicKey = try context.require(
                    X25519.PublicKey(keyData: deviceKey.publicKey.rawRepresentation),
                    "Failed to create YubiKit X25519 public key"
                )
                let importedPrivateKey = try context.require(
                    X25519.PrivateKey(scalar: deviceKey.rawRepresentation, publicKey: importedPublicKey),
                    "Failed to create YubiKit X25519 private key"
                )

                let peer = Curve25519.KeyAgreement.PrivateKey()
                let peerPublicKey = try context.require(
                    X25519.PublicKey(keyData: peer.publicKey.rawRepresentation),
                    "Failed to create peer X25519 public key"
                )
                let peerSecret = try peer.sharedSecretFromKeyAgreement(
                    with: Curve25519.KeyAgreement.PublicKey(rawRepresentation: importedPublicKey.keyData)
                ).withUnsafeBytes { Data($0) }

                try await session.putPrivateKey(
                    importedPrivateKey,
                    in: .keyManagement,
                    pinPolicy: .always,
                    touchPolicy: .never
                )
                try await session.verifyPin(defaultPIN)
                let yubiKeySecret = try await session.deriveSharedSecret(in: .keyManagement, with: peerPublicKey)
                context.expectEqual(
                    peerSecret,
                    yubiKeySecret,
                    "imported X25519 key agreement must match software ECDH"
                )

            case .rsa, .ed25519:
                try context.skip("key agreement is only defined for EC and X25519 keys")
            }
        }
    }
}
