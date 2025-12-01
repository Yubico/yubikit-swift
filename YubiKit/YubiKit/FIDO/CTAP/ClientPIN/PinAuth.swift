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

import CommonCrypto
import CryptoKit
import Foundation

/// Namespace for PIN/UV Auth Protocol types and operations.
///
/// - SeeAlso: [CTAP2 PIN/UV Auth Protocol One](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#pinProto1)
/// - SeeAlso: [CTAP2 PIN/UV Auth Protocol Two](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#pinProto2)
enum PinAuth {
    /// PIN/UV Auth Protocol version.
    ///
    /// Defines the cryptographic algorithms used for PIN/UV authentication.
    /// Protocol v1 is supported by all CTAP2 authenticators, v2 adds improved security.
    enum ProtocolVersion: Int, Sendable, CBOR.Encodable {
        /// Protocol version 1 (CTAP 2.0).
        case v1 = 1

        /// Protocol version 2 (CTAP 2.1+).
        case v2 = 2
    }

    /// Errors that can occur during PIN/UV authentication operations.
    enum Error: Swift.Error {
        case invalidPeerKey
        case keyAgreementFailed
        case encryptionFailed
        case decryptionFailed
        case pinTooShort
        case pinTooLong
        case invalidTokenSize
    }
}

// MARK: - Key Agreement

extension PinAuth.ProtocolVersion {
    /// Perform ECDH key agreement and derive shared secret.
    ///
    /// - Parameters:
    ///   - keyPair: The platform's ephemeral P-256 key pair.
    ///   - peerKey: The authenticator's public key in COSE format.
    /// - Returns: The derived shared secret (32 bytes for v1, 64 bytes for v2).
    /// - Throws: `PinAuth.Error.invalidPeerKey` if the peer key is invalid.
    func sharedSecret(
        keyPair: P256.KeyAgreement.PrivateKey,
        peerKey: COSE.Key
    ) throws(PinAuth.Error) -> Data {
        guard case .ec2(_, _, let crv, let x, let y) = peerKey, crv == 1 else {
            throw .invalidPeerKey
        }

        // Parse peer's public key
        var uncompressedPoint = Data([0x04])
        uncompressedPoint.append(x)
        uncompressedPoint.append(y)

        guard let peerPublicKey = try? P256.KeyAgreement.PublicKey(x963Representation: uncompressedPoint) else {
            throw .invalidPeerKey
        }

        // Perform ECDH
        guard let sharedSecret = try? keyPair.sharedSecretFromKeyAgreement(with: peerPublicKey) else {
            throw .keyAgreementFailed
        }

        let sharedSecretData = sharedSecret.withUnsafeBytes { Data($0) }

        // Derive protocol-specific shared secret
        switch self {
        case .v1:
            // V1: SHA-256(shared secret)
            return Data(SHA256.hash(data: sharedSecretData))

        case .v2:
            // V2: HKDF-SHA-256 to derive separate HMAC and AES keys
            let hmacKey = HKDF<SHA256>.deriveKey(
                inputKeyMaterial: SymmetricKey(data: sharedSecretData),
                salt: Data(count: 32),
                info: Data("CTAP2 HMAC key".utf8),
                outputByteCount: 32
            )

            let aesKey = HKDF<SHA256>.deriveKey(
                inputKeyMaterial: SymmetricKey(data: sharedSecretData),
                salt: Data(count: 32),
                info: Data("CTAP2 AES key".utf8),
                outputByteCount: 32
            )

            // HMAC key || AES key (64 bytes)
            var combinedKey = Data()
            hmacKey.withUnsafeBytes { combinedKey.append(contentsOf: $0) }
            aesKey.withUnsafeBytes { combinedKey.append(contentsOf: $0) }
            return combinedKey
        }
    }

    /// Encode a P-256 public key in COSE format for sending to the authenticator.
    ///
    /// - Parameter keyPair: The platform's ephemeral P-256 key pair.
    /// - Returns: The public key in COSE EC2 format.
    func coseKey(from keyPair: P256.KeyAgreement.PrivateKey) -> COSE.Key {
        let publicKey = keyPair.publicKey
        let rawRepresentation = publicKey.x963Representation
        let x = rawRepresentation.dropFirst().prefix(32)
        let y = rawRepresentation.dropFirst(33)

        return .ec2(
            alg: .other(-25),  // Per spec: "although this is NOT the algorithm actually used"
            kid: nil,
            crv: 1,
            x: Data(x),
            y: Data(y)
        )
    }
}

// MARK: - Encryption/Decryption

extension PinAuth.ProtocolVersion {
    /// Encrypt data using the shared secret.
    func encrypt(key: Data, plaintext: Data) throws(PinAuth.Error) -> Data {
        do {
            switch self {
            case .v1:
                // V1: AES-256-CBC with zero IV
                let iv = Data(count: 16)
                return try plaintext.encrypt(algorithm: CCAlgorithm(kCCAlgorithmAES), key: key, iv: iv)

            case .v2:
                // V2: AES-256-CBC with random IV, using AES key (last 32 bytes)
                let aesKey = key.suffix(32)
                var iv = Data(count: 16)
                _ = iv.withUnsafeMutableBytes { buffer in
                    SecRandomCopyBytes(kSecRandomDefault, 16, buffer.baseAddress!)
                }
                let ciphertext = try plaintext.encrypt(algorithm: CCAlgorithm(kCCAlgorithmAES), key: aesKey, iv: iv)
                return iv + ciphertext
            }
        } catch {
            throw .encryptionFailed
        }
    }

    /// Decrypt data using the shared secret.
    func decrypt(key: Data, ciphertext: Data) throws(PinAuth.Error) -> Data {
        do {
            switch self {
            case .v1:
                // V1: AES-256-CBC with zero IV
                let iv = Data(count: 16)
                return try ciphertext.decrypt(algorithm: CCAlgorithm(kCCAlgorithmAES), key: key, iv: iv)

            case .v2:
                // V2: Extract IV from ciphertext, use AES key (last 32 bytes)
                guard ciphertext.count > 16 else {
                    throw PinAuth.Error.decryptionFailed
                }
                let aesKey = key.suffix(32)
                let iv = ciphertext.prefix(16)
                let actualCiphertext = ciphertext.dropFirst(16)
                return try actualCiphertext.decrypt(algorithm: CCAlgorithm(kCCAlgorithmAES), key: aesKey, iv: iv)
            }
        } catch {
            throw .decryptionFailed
        }
    }
}

// MARK: - Authentication

extension PinAuth.ProtocolVersion {
    /// Compute authentication parameter for PIN/UV operations.
    func authenticate(key: Data, message: Data) -> Data {
        // V1 uses full key, V2 uses first 32 bytes (HMAC key)
        let hmacKey = self == .v1 ? key : key.prefix(32)

        let hmac = HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: hmacKey))
        // V1: truncate to 16 bytes, V2: full 32 bytes
        return self == .v1 ? Data(hmac.prefix(16)) : Data(hmac)
    }
}

// MARK: - PIN Preparation

extension PinAuth.ProtocolVersion {
    /// Validate and pad a PIN to 64 bytes as required by CTAP2.
    ///
    /// - Parameter pin: The PIN string to validate and pad.
    /// - Returns: The PIN padded to 64 bytes.
    /// - Throws: `PinAuth.Error.pinTooShort` if PIN has fewer than 4 Unicode code points,
    ///           `PinAuth.Error.pinTooLong` if PIN exceeds 63 bytes UTF-8.
    func padPin(_ pin: String) throws(PinAuth.Error) -> Data {
        // Normalize to NFC per CTAP2 spec §6.5.1
        let normalizedPin = pin.precomposedStringWithCanonicalMapping
        guard normalizedPin.unicodeScalars.count >= 4 else {  // min 4 Unicode code points
            throw .pinTooShort
        }

        let pinData = Data(normalizedPin.utf8)
        guard pinData.count <= 63 else {  // max 63 UTF-8 bytes
            throw .pinTooLong
        }

        var padded = pinData
        padded.append(Data(count: 64 - pinData.count))
        return padded
    }
}
