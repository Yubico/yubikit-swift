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

import Foundation
import Security

/// SecKey-based cryptographic operations for RSA and EC keys.
internal enum SecKeyOperations {

    // MARK: - RSA Key Generation

    /// Creates a temporary RSA key pair.
    /// - Parameter bitCount: The key size in bits (e.g., 1024, 2048).
    /// - Returns: A tuple of (privateKey, publicKey).
    /// - Throws: `CryptoError.keyCreationFailed` if key generation fails.
    internal static func generateRSAKeyPair(bitCount: Int) throws(CryptoError) -> (privateKey: SecKey, publicKey: SecKey) {
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits: bitCount
        ]

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error),
              let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw .keyCreationFailed(error?.takeRetainedValue())
        }

        return (privateKey, publicKey)
    }

    // MARK: - RSA Signing

    /// Signs data using an RSA private key.
    /// - Parameters:
    ///   - data: The data to sign.
    ///   - privateKey: The RSA private key.
    ///   - algorithm: The signature algorithm.
    /// - Returns: The signature.
    /// - Throws: `CryptoError.signingFailed` if signing fails.
    internal static func rsaSign(
        _ data: Data,
        privateKey: SecKey,
        algorithm: SecKeyAlgorithm
    ) throws(CryptoError) -> Data {
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(privateKey, algorithm, data as CFData, &error) else {
            throw .signingFailed(error?.takeRetainedValue())
        }
        return signature as Data
    }

    // MARK: - RSA Encryption/Decryption

    /// Encrypts data using an RSA public key.
    /// - Parameters:
    ///   - data: The data to encrypt.
    ///   - publicKey: The RSA public key.
    ///   - algorithm: The encryption algorithm.
    /// - Returns: The encrypted data.
    /// - Throws: `CryptoError.encryptionFailed` if encryption fails.
    internal static func rsaEncrypt(
        _ data: Data,
        publicKey: SecKey,
        algorithm: SecKeyAlgorithm
    ) throws(CryptoError) -> Data {
        var error: Unmanaged<CFError>?
        guard let encrypted = SecKeyCreateEncryptedData(publicKey, algorithm, data as CFData, &error) else {
            throw .encryptionFailed(error?.takeRetainedValue())
        }
        return encrypted as Data
    }

    /// Decrypts data using an RSA private key.
    /// - Parameters:
    ///   - data: The data to decrypt.
    ///   - privateKey: The RSA private key.
    ///   - algorithm: The decryption algorithm.
    /// - Returns: The decrypted data.
    /// - Throws: `CryptoError.decryptionFailed` if decryption fails.
    internal static func rsaDecrypt(
        _ data: Data,
        privateKey: SecKey,
        algorithm: SecKeyAlgorithm
    ) throws(CryptoError) -> Data {
        var error: Unmanaged<CFError>?
        guard let decrypted = SecKeyCreateDecryptedData(privateKey, algorithm, data as CFData, &error) else {
            throw .decryptionFailed(error?.takeRetainedValue())
        }
        return decrypted as Data
    }

    // MARK: - ECDH Key Exchange

    /// Performs ECDH key exchange using SecKey.
    /// - Parameters:
    ///   - privateKey: The EC private key.
    ///   - publicKey: The peer's EC public key.
    /// - Returns: The shared secret.
    /// - Throws: `CryptoError.keyAgreementFailed` if key exchange fails.
    internal static func ecdhKeyExchange(
        privateKey: SecKey,
        publicKey: SecKey
    ) throws(CryptoError) -> Data {
        var error: Unmanaged<CFError>?
        let params: [String: Any] = [:]
        guard let secretData = SecKeyCopyKeyExchangeResult(
            privateKey,
            .ecdhKeyExchangeStandard,
            publicKey,
            params as CFDictionary,
            &error
        ) else {
            throw .keyAgreementFailed
        }
        return secretData as Data
    }
}
