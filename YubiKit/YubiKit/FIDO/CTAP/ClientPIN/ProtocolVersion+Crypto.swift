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

// MARK: - Key Agreement

extension CTAP2.ClientPin.ProtocolVersion {
    /// Perform ECDH key agreement and derive shared secret.
    ///
    /// - Parameters:
    ///   - keyPair: The platform's ephemeral P-256 key pair.
    ///   - peerKey: The authenticator's public key in COSE format.
    /// - Returns: The derived shared secret (32 bytes for v1, 64 bytes for v2).
    /// - Throws: `CTAP2.SessionError.cryptoError` if the peer key is invalid or key agreement fails.
    func sharedSecret(
        keyPair: P256.KeyAgreement.PrivateKey,
        peerKey: COSE.Key
    ) throws(CTAP2.SessionError) -> Data {
        guard case .ec2(_, _, let crv, let x, let y) = peerKey, crv == 1 else {
            throw .cryptoError("Invalid authenticator COSE key: expected EC2 P-256", error: nil, source: .here())
        }

        // Parse peer's public key
        var uncompressedPoint = Data([0x04])
        uncompressedPoint.append(x)
        uncompressedPoint.append(y)

        guard let peerPublicKey = try? P256.KeyAgreement.PublicKey(x963Representation: uncompressedPoint) else {
            throw .cryptoError("Invalid authenticator public key format", error: nil, source: .here())
        }

        // Perform ECDH
        guard let sharedSecret = try? keyPair.sharedSecretFromKeyAgreement(with: peerPublicKey) else {
            throw .cryptoError("ECDH key agreement failed", error: nil, source: .here())
        }

        let sharedSecretData = sharedSecret.withUnsafeBytes { Data($0) }

        // Derive protocol-specific shared secret
        switch self {
        case .v1:
            // V1: SHA-256(shared secret)
            return sharedSecretData.sha256()

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

extension CTAP2.ClientPin.ProtocolVersion {
    /// Encrypt data using the shared secret.
    func encrypt(key: Data, plaintext: Data) throws(CTAP2.SessionError) -> Data {
        do {
            switch self {
            case .v1:
                // V1: AES-256-CBC with zero IV
                let iv = Data(count: 16)
                return try plaintext.encrypt(algorithm: CCAlgorithm(kCCAlgorithmAES), key: key, iv: iv)

            case .v2:
                // V2: AES-256-CBC with random IV, using AES key (last 32 bytes)
                let aesKey = key.suffix(32)
                let iv = try Data.random(length: 16)
                let ciphertext = try plaintext.encrypt(algorithm: CCAlgorithm(kCCAlgorithmAES), key: aesKey, iv: iv)
                return iv + ciphertext
            }
        } catch {
            throw .cryptoError("PIN protocol encryption failed", error: error, source: .here())
        }
    }

    /// Decrypt data using the shared secret.
    func decrypt(key: Data, ciphertext: Data) throws(CTAP2.SessionError) -> Data {
        do {
            switch self {
            case .v1:
                // V1: AES-256-CBC with zero IV
                let iv = Data(count: 16)
                return try ciphertext.decrypt(algorithm: CCAlgorithm(kCCAlgorithmAES), key: key, iv: iv)

            case .v2:
                // V2: Extract IV from ciphertext, use AES key (last 32 bytes)
                guard ciphertext.count > 16 else {
                    throw CTAP2.SessionError.cryptoError(
                        "PIN protocol decryption failed: ciphertext too short",
                        error: nil,
                        source: .here()
                    )
                }
                let aesKey = key.suffix(32)
                let iv = ciphertext.prefix(16)
                let actualCiphertext = ciphertext.dropFirst(16)
                return try actualCiphertext.decrypt(algorithm: CCAlgorithm(kCCAlgorithmAES), key: aesKey, iv: iv)
            }
        } catch let error as CTAP2.SessionError {
            throw error
        } catch {
            throw .cryptoError("PIN protocol decryption failed", error: error, source: .here())
        }
    }
}

// MARK: - Authentication

extension CTAP2.ClientPin.ProtocolVersion {
    /// Compute authentication parameter for PIN/UV operations.
    func authenticate(key: Data, message: Data) -> Data {
        // V1 uses full key, V2 uses first 32 bytes (HMAC key)
        let hmacKey = self == .v1 ? key : Data(key.prefix(32))

        let hmac = message.hmacSha256(key: hmacKey)
        // V1: truncate to 16 bytes, V2: full 32 bytes
        return self == .v1 ? hmac.prefix(16) : hmac
    }
}

// MARK: - PIN Preparation

extension CTAP2.ClientPin.ProtocolVersion {
    /// Validate and pad a PIN to 64 bytes as required by CTAP2.
    ///
    /// - Parameter pin: The PIN string to validate and pad.
    /// - Returns: The PIN padded to 64 bytes.
    /// - Throws: `CTAP2.SessionError.illegalArgument` if PIN has fewer than 4 Unicode code points
    ///           or exceeds 63 bytes UTF-8.
    func padPin(_ pin: String) throws(CTAP2.SessionError) -> Data {
        // Normalize to NFC per CTAP2 spec §6.5.1
        let normalizedPin = pin.precomposedStringWithCanonicalMapping
        guard normalizedPin.unicodeScalars.count >= 4 else {  // min 4 Unicode code points
            throw .illegalArgument("PIN must have at least 4 Unicode code points", source: .here())
        }

        let pinData = Data(normalizedPin.utf8)
        guard pinData.count <= 63 else {  // max 63 UTF-8 bytes
            throw .illegalArgument("PIN must be at most 63 UTF-8 bytes", source: .here())
        }

        var padded = pinData
        padded.append(Data(count: 64 - pinData.count))
        return padded
    }
}
