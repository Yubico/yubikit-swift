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

/// PIN/UV authentication protocol with version-specific cryptography.
///
/// - SeeAlso: [CTAP2.3 PIN/UV Auth Protocol One](https://fidoalliance.org/specs/fido-v2.3-rd-20251023/fido-client-to-authenticator-protocol-v2.3-rd-20251023.html#pinProto1)
/// - SeeAlso: [CTAP2.3 PIN/UV Auth Protocol Two](https://fidoalliance.org/specs/fido-v2.3-rd-20251023/fido-client-to-authenticator-protocol-v2.3-rd-20251023.html#pinProto2)
public struct PinAuth: Sendable {
    /// Protocol version enum.
    public enum Version: Int, Sendable {
        /// Protocol version 1 (CTAP 2.0).
        case v1 = 1

        /// Protocol version 2 (CTAP 2.1+).
        case v2 = 2
    }

    /// The protocol version.
    public let version: Version

    /// Platform's ephemeral ECDH key pair for key agreement.
    public let keyPair: P256.KeyAgreement.PrivateKey

    private init(version: Version, keyPair: P256.KeyAgreement.PrivateKey) {
        self.version = version
        self.keyPair = keyPair
    }

    public static var `default`: PinAuth {
        .v1()
    }

    public static func v1() -> PinAuth {
        PinAuth(version: .v1, keyPair: P256.KeyAgreement.PrivateKey())
    }

    public static func v2() -> PinAuth {
        PinAuth(version: .v2, keyPair: P256.KeyAgreement.PrivateKey())
    }
}

// MARK: - CBOR Encoding

extension PinAuth.Version: CBOR.Encodable {}

// MARK: - Key Agreement

extension PinAuth {
    /// Perform ECDH key agreement with the authenticator's public key.
    func keyAgreement(peerKey: COSE.Key) throws -> KeyAgreementResult {
        guard case .ec2(_, _, let crv, let x, let y) = peerKey, crv == 1 else {
            throw PinAuthError.invalidPeerKey
        }

        var uncompressedPoint = Data([0x04])
        uncompressedPoint.append(x)
        uncompressedPoint.append(y)

        guard let peerPublicKey = try? P256.KeyAgreement.PublicKey(x963Representation: uncompressedPoint) else {
            throw PinAuthError.invalidPeerKey
        }

        guard let sharedSecret = try? keyPair.sharedSecretFromKeyAgreement(with: peerPublicKey) else {
            throw PinAuthError.keyAgreementFailed
        }

        let sharedSecretData = sharedSecret.withUnsafeBytes { Data($0) }

        switch version {
        case .v1:
            // V1: SHA-256(shared secret)
            let kdf = SHA256.hash(data: sharedSecretData)
            return KeyAgreementResult(sharedSecret: Data(kdf))

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
            return KeyAgreementResult(sharedSecret: combinedKey)
        }
    }
}

// MARK: - Encryption/Decryption

extension PinAuth {
    /// Encrypt data using the shared secret.
    func encrypt(key: Data, plaintext: Data) throws -> Data {
        switch version {
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
    }

    /// Decrypt data using the shared secret.
    func decrypt(key: Data, ciphertext: Data) throws -> Data {
        switch version {
        case .v1:
            // V1: AES-256-CBC with zero IV
            let iv = Data(count: 16)
            return try ciphertext.decrypt(algorithm: CCAlgorithm(kCCAlgorithmAES), key: key, iv: iv)

        case .v2:
            // V2: Extract IV from ciphertext, use AES key (last 32 bytes)
            guard ciphertext.count > 16 else {
                throw PinAuthError.decryptionFailed
            }
            let aesKey = key.suffix(32)
            let iv = ciphertext.prefix(16)
            let actualCiphertext = ciphertext.dropFirst(16)
            return try actualCiphertext.decrypt(algorithm: CCAlgorithm(kCCAlgorithmAES), key: aesKey, iv: iv)
        }
    }
}

// MARK: - Authentication

extension PinAuth {
    /// Compute authentication parameter for PIN/UV operations.
    func authenticate(key: Data, message: Data) -> Data {
        // V1 uses full key, V2 uses first 32 bytes (HMAC key)
        let hmacKey = version == .v1 ? key : key.prefix(32)

        let hmac = HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: hmacKey))
        // V1: truncate to 16 bytes, V2: full 32 bytes
        return version == .v1 ? Data(hmac.prefix(16)) : Data(hmac)
    }
}

// MARK: - Platform Key

extension PinAuth {
    /// Encode the platform's public key in COSE format for the authenticator.
    func platformKeyAgreementKey() -> COSE.Key {
        let publicKey = keyPair.publicKey
        let rawRepresentation = publicKey.x963Representation
        let x = rawRepresentation.dropFirst().prefix(32)
        let y = rawRepresentation.dropFirst(33)

        return .ec2(
            alg: .other(-25),  // ECDH-ES+HKDF-256
            kid: nil,
            crv: 1,
            x: Data(x),
            y: Data(y)
        )
    }
}

// MARK: - PIN Preparation

extension PinAuth {
    /// Minimum PIN length (4 Unicode code points per CTAP2 spec).
    public static let minPinLength = 4

    /// Maximum PIN length (63 bytes UTF-8 per CTAP2 spec).
    public static let maxPinLengthBytes = 63

    /// Pad a PIN to 64 bytes as required by CTAP2.
    func padPIN(_ pin: String) -> Data {
        var data = Data(pin.utf8)
        if data.count < 64 {
            data.append(Data(count: 64 - data.count))
        }
        return data
    }

    /// Prepare and validate a PIN for CTAP2 operations.
    public static func preparePin(_ pin: String, padded: Bool) throws -> Data {
        guard pin.unicodeScalars.count >= minPinLength else {
            throw PinAuthError.pinTooShort
        }

        let pinData = Data(pin.utf8)
        guard pinData.count <= maxPinLengthBytes else {
            throw PinAuthError.pinTooLong
        }

        if padded {
            var data = pinData
            data.append(Data(count: 64 - data.count))
            return data
        } else {
            return pinData
        }
    }
}

// MARK: - Supporting Types

/// Result of ECDH key agreement operation.
struct KeyAgreementResult: Sendable {
    /// Shared secret (32 bytes for v1, 64 bytes for v2).
    let sharedSecret: Data
}

/// Errors that can occur during PIN authentication operations.
public enum PinAuthError: Error {
    case invalidPeerKey
    case keyAgreementFailed
    case encryptionFailed
    case decryptionFailed
    case pinTooShort
    case pinTooLong
}
